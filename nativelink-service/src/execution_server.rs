// Copyright 2024 The NativeLink Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use std::convert::Into;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::stream::unfold;
use futures::{Stream, StreamExt};
use nativelink_config::cas_server::{ExecutionConfig, InstanceName};
use nativelink_error::{make_input_err, Error, ResultExt};
use nativelink_proto::build::bazel::remote::execution::v2::execution_server::{
    Execution, ExecutionServer as Server,
};
use nativelink_proto::build::bazel::remote::execution::v2::{
    Action, Command, ExecuteRequest, WaitExecutionRequest,
};
use nativelink_proto::google::longrunning::Operation;
use nativelink_store::ac_utils::get_and_decode_digest;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::action_messages::{
    ActionInfo, ActionUniqueKey, ActionUniqueQualifier, OperationId, DEFAULT_EXECUTION_PRIORITY,
};
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::{make_ctx_for_hash_func, DigestHasherFunc};
use nativelink_util::operation_state_manager::{
    ActionStateResult, ClientStateManager, OperationFilter,
};
use nativelink_util::origin_event::OriginEventContext;
use nativelink_util::store_trait::Store;
use tonic::{Request, Response, Status};
use tracing::{error_span, event, instrument, Level};

type InstanceInfoName = String;

struct NativelinkOperationId {
    instance_name: InstanceInfoName,
    client_operation_id: OperationId,
}

impl NativelinkOperationId {
    const fn new(instance_name: InstanceInfoName, client_operation_id: OperationId) -> Self {
        Self {
            instance_name,
            client_operation_id,
        }
    }

    fn from_name(name: &str) -> Result<Self, Error> {
        let (instance_name, name) = name
            .split_once('/')
            .err_tip(|| "Expected instance_name and name to be separated by '/'")?;
        Ok(NativelinkOperationId::new(
            instance_name.to_string(),
            OperationId::from(name),
        ))
    }
}

impl fmt::Display for NativelinkOperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.instance_name, self.client_operation_id)
    }
}

struct InstanceInfo {
    scheduler: Arc<dyn ClientStateManager>,
    cas_store: Store,
}

impl InstanceInfo {
    async fn build_action_info(
        &self,
        instance_name: String,
        action_digest: DigestInfo,
        action: Action,
        priority: i32,
        skip_cache_lookup: bool,
        digest_function: DigestHasherFunc,
    ) -> Result<ActionInfo, Error> {
        let command_digest = DigestInfo::try_from(
            action
                .command_digest
                .clone()
                .err_tip(|| "Expected command_digest to exist")?,
        )
        .err_tip(|| "Could not decode command digest")?;

        let input_root_digest = DigestInfo::try_from(
            action
                .clone()
                .input_root_digest
                .err_tip(|| "Expected input_digest_root")?,
        )?;
        let timeout = action.timeout.map_or(Duration::MAX, |v| {
            Duration::new(v.seconds as u64, v.nanos as u32)
        });

        let mut platform_properties = HashMap::new();
        if let Some(platform) = action.platform {
            for property in platform.properties {
                platform_properties.insert(property.name, property.value);
            }
        }

        // Goma puts the properties in the Command.
        if platform_properties.is_empty() {
            let command =
                get_and_decode_digest::<Command>(&self.cas_store, command_digest.into()).await?;
            if let Some(platform) = command.platform {
                for property in platform.properties {
                    platform_properties.insert(property.name, property.value);
                }
            }
        }

        let action_key = ActionUniqueKey {
            instance_name,
            digest_function,
            digest: action_digest,
        };
        let unique_qualifier = if skip_cache_lookup {
            ActionUniqueQualifier::Uncachable(action_key)
        } else {
            ActionUniqueQualifier::Cachable(action_key)
        };

        Ok(ActionInfo {
            command_digest,
            input_root_digest,
            timeout,
            platform_properties,
            priority,
            load_timestamp: UNIX_EPOCH,
            insert_timestamp: SystemTime::now(),
            unique_qualifier,
        })
    }
}

pub struct ExecutionServer {
    instance_infos: HashMap<InstanceName, InstanceInfo>,
}

type ExecuteStream = Pin<Box<dyn Stream<Item = Result<Operation, Status>> + Send + 'static>>;

impl ExecutionServer {
    pub fn new(
        config: &HashMap<InstanceName, ExecutionConfig>,
        scheduler_map: &HashMap<String, Arc<dyn ClientStateManager>>,
        store_manager: &StoreManager,
    ) -> Result<Self, Error> {
        let mut instance_infos = HashMap::with_capacity(config.len());
        for (instance_name, exec_cfg) in config {
            let cas_store = store_manager
                .get_store(&exec_cfg.cas_store)
                .ok_or_else(|| {
                    make_input_err!("'cas_store': '{}' does not exist", exec_cfg.cas_store)
                })?;
            let scheduler = scheduler_map
                .get(&exec_cfg.scheduler)
                .err_tip(|| {
                    format!(
                        "Scheduler needs config for '{}' because it exists in execution",
                        exec_cfg.scheduler
                    )
                })?
                .clone();

            instance_infos.insert(
                instance_name.to_string(),
                InstanceInfo {
                    scheduler,
                    cas_store,
                },
            );
        }
        Ok(Self { instance_infos })
    }

    pub fn into_service(self) -> Server<ExecutionServer> {
        Server::new(self)
    }

    fn to_execute_stream(
        nl_client_operation_id: &NativelinkOperationId,
        action_listener: Box<dyn ActionStateResult>,
    ) -> impl Stream<Item = Result<Operation, Status>> + Send + 'static {
        let client_operation_id = OperationId::from(nl_client_operation_id.to_string());
        unfold(Some(action_listener), move |maybe_action_listener| {
            let client_operation_id = client_operation_id.clone();
            async move {
                let mut action_listener = maybe_action_listener?;
                match action_listener.changed().await {
                    Ok(action_update) => {
                        event!(Level::INFO, ?action_update, "Execute Resp Stream");
                        // If the action is finished we won't be sending any more updates.
                        let maybe_action_listener = if action_update.stage.is_finished() {
                            None
                        } else {
                            Some(action_listener)
                        };
                        Some((
                            Ok(action_update.as_operation(client_operation_id)),
                            maybe_action_listener,
                        ))
                    }
                    Err(err) => {
                        event!(Level::ERROR, ?err, "Error in action_listener stream");
                        Some((Err(err.into()), None))
                    }
                }
            }
        })
    }

    async fn inner_execute(
        &self,
        request: ExecuteRequest,
    ) -> Result<impl Stream<Item = Result<Operation, Status>> + Send + 'static, Error> {
        let instance_name = request.instance_name;

        let instance_info = self
            .instance_infos
            .get(&instance_name)
            .err_tip(|| "Instance name '{}' not configured")?;

        let digest = DigestInfo::try_from(
            request
                .action_digest
                .err_tip(|| "Expected action_digest to exist")?,
        )
        .err_tip(|| "Failed to unwrap action cache")?;

        let priority = request
            .execution_policy
            .map_or(DEFAULT_EXECUTION_PRIORITY, |p| p.priority);

        let action =
            get_and_decode_digest::<Action>(&instance_info.cas_store, digest.into()).await?;
        let action_info = instance_info
            .build_action_info(
                instance_name.clone(),
                digest,
                action,
                priority,
                request.skip_cache_lookup,
                request
                    .digest_function
                    .try_into()
                    .err_tip(|| "Could not convert digest function in inner_execute()")?,
            )
            .await?;

        let action_listener = instance_info
            .scheduler
            .add_action(OperationId::default(), Arc::new(action_info))
            .await
            .err_tip(|| "Failed to schedule task")?;

        Ok(Box::pin(Self::to_execute_stream(
            &NativelinkOperationId::new(
                instance_name,
                action_listener
                    .as_state()
                    .await
                    .err_tip(|| "In ExecutionServer::inner_execute")?
                    .client_operation_id
                    .clone(),
            ),
            action_listener,
        )))
    }

    async fn inner_wait_execution(
        &self,
        request: WaitExecutionRequest,
    ) -> Result<impl Stream<Item = Result<Operation, Status>> + Send + 'static, Status> {
        let nl_operation_id = NativelinkOperationId::from_name(&request.name)
            .err_tip(|| "Failed to parse operation_id in ExecutionServer::wait_execution")?;
        let Some(instance_info) = self.instance_infos.get(&nl_operation_id.instance_name) else {
            return Err(Status::not_found(format!(
                "No scheduler with the instance name {}",
                nl_operation_id.instance_name,
            )));
        };
        let Some(rx) = instance_info
            .scheduler
            .filter_operations(OperationFilter {
                client_operation_id: Some(nl_operation_id.client_operation_id.clone()),
                ..Default::default()
            })
            .await
            .err_tip(|| "Error running find_existing_action in ExecutionServer::wait_execution")?
            .next()
            .await
        else {
            return Err(Status::not_found("Failed to find existing task"));
        };
        Ok(Self::to_execute_stream(&nl_operation_id, rx))
    }
}

#[tonic::async_trait]
impl Execution for ExecutionServer {
    type ExecuteStream = ExecuteStream;
    type WaitExecutionStream = ExecuteStream;

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        err,
        level = Level::ERROR,
        skip_all,
        fields(request = ?grpc_request.get_ref())
    )]
    async fn execute(
        &self,
        grpc_request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteStream>, Status> {
        let request = grpc_request.into_inner();
        let ctx = OriginEventContext::new(|| &request).await;
        let resp = make_ctx_for_hash_func(request.digest_function)
            .err_tip(|| "In ExecutionServer::execute")?
            .wrap_async(
                error_span!("execution_server_execute"),
                self.inner_execute(request),
            )
            .await
            .map(|stream| ctx.wrap_stream(stream))
            .map(Response::new)
            .err_tip(|| "Failed on execute() command")
            .map_err(Into::into);
        ctx.emit(|| &resp).await;
        resp
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        err,
        level = Level::ERROR,
        skip_all,
        fields(request = ?grpc_request.get_ref())
    )]
    async fn wait_execution(
        &self,
        grpc_request: Request<WaitExecutionRequest>,
    ) -> Result<Response<ExecuteStream>, Status> {
        let request = grpc_request.into_inner();
        let ctx = OriginEventContext::new(|| &request).await;
        let resp = self
            .inner_wait_execution(request)
            .await
            .err_tip(|| "Failed on wait_execution() command")
            .map(|stream| ctx.wrap_stream(stream))
            .map(Response::new)
            .map_err(Into::into);

        if resp.is_ok() {
            event!(Level::DEBUG, return = "Ok(<stream>)");
        }
        resp
    }
}
