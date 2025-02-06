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
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::stream::unfold;
use futures::Stream;
use nativelink_config::cas_server::WorkerApiConfig;
use nativelink_error::{make_err, Code, Error, ResultExt};
use nativelink_proto::com::github::trace_machina::nativelink::remote_execution::worker_api_server::{
    WorkerApi, WorkerApiServer as Server,
};
use nativelink_proto::com::github::trace_machina::nativelink::remote_execution::{
    execute_result, ConnectWorkerRequest, ExecuteResult, GoingAwayRequest, KeepAliveRequest, UpdateForWorker
};
use nativelink_scheduler::worker::Worker;
use nativelink_scheduler::worker_scheduler::WorkerScheduler;
use nativelink_util::background_spawn;
use nativelink_util::action_messages::{OperationId, WorkerId};
use nativelink_util::operation_state_manager::UpdateOperationType;
use nativelink_util::platform_properties::PlatformProperties;
use rand::RngCore;
use tokio::sync::mpsc;
use tokio::time::interval;
use tonic::{Request, Response, Status};
use tracing::{event, instrument, Level};
use uuid::Uuid;

pub type ConnectWorkerStream =
    Pin<Box<dyn Stream<Item = Result<UpdateForWorker, Status>> + Send + Sync + 'static>>;

pub type NowFn = Box<dyn Fn() -> Result<Duration, Error> + Send + Sync>;

pub struct WorkerApiServer {
    scheduler: Arc<dyn WorkerScheduler>,
    now_fn: NowFn,
    node_id: [u8; 6],
}

impl WorkerApiServer {
    pub fn new(
        config: &WorkerApiConfig,
        schedulers: &HashMap<String, Arc<dyn WorkerScheduler>>,
    ) -> Result<Self, Error> {
        let node_id = {
            let mut rng = rand::thread_rng();
            let mut out = [0; 6];
            rng.fill_bytes(&mut out);
            out
        };
        for scheduler in schedulers.values() {
            // This will protect us from holding a reference to the scheduler forever in the
            // event our ExecutionServer dies. Our scheduler is a weak ref, so the spawn will
            // eventually see the Arc went away and return.
            let weak_scheduler = Arc::downgrade(scheduler);
            background_spawn!("worker_api_server", async move {
                let mut ticker = interval(Duration::from_secs(1));
                loop {
                    ticker.tick().await;
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Error: system time is now behind unix epoch");
                    match weak_scheduler.upgrade() {
                        Some(scheduler) => {
                            if let Err(err) =
                                scheduler.remove_timedout_workers(timestamp.as_secs()).await
                            {
                                event!(Level::ERROR, ?err, "Failed to remove_timedout_workers",);
                            }
                        }
                        // If we fail to upgrade, our service is probably destroyed, so return.
                        None => return,
                    }
                }
            });
        }

        Self::new_with_now_fn(
            config,
            schedulers,
            Box::new(move || {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| make_err!(Code::Internal, "System time is now behind unix epoch"))
            }),
            node_id,
        )
    }

    /// Same as `new()`, but you can pass a custom `now_fn`, that returns a Duration since `UNIX_EPOCH`
    /// representing the current time. Used mostly in  unit tests.
    pub fn new_with_now_fn(
        config: &WorkerApiConfig,
        schedulers: &HashMap<String, Arc<dyn WorkerScheduler>>,
        now_fn: NowFn,
        node_id: [u8; 6],
    ) -> Result<Self, Error> {
        let scheduler = schedulers
            .get(&config.scheduler)
            .err_tip(|| {
                format!(
                    "Scheduler needs config for '{}' because it exists in worker_api",
                    config.scheduler
                )
            })?
            .clone();
        Ok(Self {
            scheduler,
            now_fn,
            node_id,
        })
    }

    pub fn into_service(self) -> Server<WorkerApiServer> {
        Server::new(self)
    }

    async fn inner_connect_worker(
        &self,
        connect_worker_request: ConnectWorkerRequest,
    ) -> Result<Response<ConnectWorkerStream>, Error> {
        let (tx, rx) = mpsc::unbounded_channel();

        // First convert our proto platform properties into one our scheduler understands.
        let platform_properties = {
            let mut platform_properties = PlatformProperties::default();
            for property in connect_worker_request.properties {
                let platform_property_value = self
                    .scheduler
                    .get_platform_property_manager()
                    .make_prop_value(&property.name, &property.value)
                    .err_tip(|| "Bad Property during connect_worker()")?;
                platform_properties
                    .properties
                    .insert(property.name.clone(), platform_property_value);
            }
            platform_properties
        };

        // Now register the worker with the scheduler.
        let worker_id = {
            let worker_id = WorkerId(format!(
                "{}{}",
                connect_worker_request.worker_id_prefix,
                Uuid::now_v6(&self.node_id).hyphenated()
            ));
            let worker = Worker::new(
                worker_id.clone(),
                platform_properties,
                tx,
                (self.now_fn)()?.as_secs(),
            );
            self.scheduler
                .add_worker(worker)
                .await
                .err_tip(|| "Failed to add worker in inner_connect_worker()")?;
            worker_id
        };

        Ok(Response::new(Box::pin(unfold(
            (rx, worker_id),
            move |state| async move {
                let (mut rx, worker_id) = state;
                if let Some(update_for_worker) = rx.recv().await {
                    return Some((Ok(update_for_worker), (rx, worker_id)));
                }
                event!(
                    Level::WARN,
                    ?worker_id,
                    "UpdateForWorker channel was closed, thus closing connection to worker node",
                );

                None
            },
        ))))
    }

    async fn inner_keep_alive(
        &self,
        keep_alive_request: KeepAliveRequest,
    ) -> Result<Response<()>, Error> {
        let worker_id: WorkerId = keep_alive_request.worker_id.into();
        self.scheduler
            .worker_keep_alive_received(&worker_id, (self.now_fn)()?.as_secs())
            .await
            .err_tip(|| "Could not process keep_alive from worker in inner_keep_alive()")?;
        Ok(Response::new(()))
    }

    async fn inner_going_away(
        &self,
        going_away_request: GoingAwayRequest,
    ) -> Result<Response<()>, Error> {
        let worker_id: WorkerId = going_away_request.worker_id.into();
        self.scheduler
            .remove_worker(&worker_id)
            .await
            .err_tip(|| "While calling WorkerApiServer::inner_going_away")?;
        Ok(Response::new(()))
    }

    async fn inner_execution_response(
        &self,
        execute_result: ExecuteResult,
    ) -> Result<Response<()>, Error> {
        let worker_id: WorkerId = execute_result.worker_id.into();
        let operation_id = OperationId::from(execute_result.operation_id);

        match execute_result
            .result
            .err_tip(|| "Expected result to exist in ExecuteResult")?
        {
            execute_result::Result::ExecuteResponse(finished_result) => {
                let action_stage = finished_result
                    .try_into()
                    .err_tip(|| "Failed to convert ExecuteResponse into an ActionStage")?;
                self.scheduler
                    .update_action(
                        &worker_id,
                        &operation_id,
                        UpdateOperationType::UpdateWithActionStage(action_stage),
                    )
                    .await
                    .err_tip(|| format!("Failed to operation {operation_id:?}"))?;
            }
            execute_result::Result::InternalError(e) => {
                self.scheduler
                    .update_action(
                        &worker_id,
                        &operation_id,
                        UpdateOperationType::UpdateWithError(e.into()),
                    )
                    .await
                    .err_tip(|| format!("Failed to operation {operation_id:?}"))?;
            }
        }
        Ok(Response::new(()))
    }
}

#[tonic::async_trait]
impl WorkerApi for WorkerApiServer {
    type ConnectWorkerStream = ConnectWorkerStream;

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        err,
        level = Level::ERROR,
        skip_all,
        fields(request = ?grpc_request.get_ref())
    )]
    async fn connect_worker(
        &self,
        grpc_request: Request<ConnectWorkerRequest>,
    ) -> Result<Response<Self::ConnectWorkerStream>, Status> {
        let resp = self
            .inner_connect_worker(grpc_request.into_inner())
            .await
            .map_err(Into::into);
        if resp.is_ok() {
            event!(Level::DEBUG, return = "Ok(<stream>)");
        }
        resp
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        err,
        ret(level = Level::INFO),
        level = Level::INFO,
        skip_all,
        fields(request = ?grpc_request.get_ref())
    )]
    async fn keep_alive(
        &self,
        grpc_request: Request<KeepAliveRequest>,
    ) -> Result<Response<()>, Status> {
        self.inner_keep_alive(grpc_request.into_inner())
            .await
            .map_err(Into::into)
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        err,
        ret(level = Level::INFO),
        level = Level::ERROR,
        skip_all,
        fields(request = ?grpc_request.get_ref())
    )]
    async fn going_away(
        &self,
        grpc_request: Request<GoingAwayRequest>,
    ) -> Result<Response<()>, Status> {
        self.inner_going_away(grpc_request.into_inner())
            .await
            .map_err(Into::into)
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        err,
        ret(level = Level::INFO),
        level = Level::ERROR,
        skip_all,
        fields(request = ?grpc_request.get_ref())
    )]
    async fn execution_response(
        &self,
        grpc_request: Request<ExecuteResult>,
    ) -> Result<Response<()>, Status> {
        self.inner_execution_response(grpc_request.into_inner())
            .await
            .map_err(Into::into)
    }
}
