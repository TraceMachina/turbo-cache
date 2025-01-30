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
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_lock::Mutex as AsyncMutex;
use async_trait::async_trait;
use bytes::Bytes;
use nativelink_config::cas_server::WorkerApiConfig;
use nativelink_config::schedulers::WorkerAllocationStrategy;
use nativelink_error::{Error, ResultExt};
use nativelink_macro::nativelink_test;
use nativelink_metric::MetricsComponent;
use nativelink_proto::build::bazel::remote::execution::v2::{
    ActionResult as ProtoActionResult, ExecuteResponse, ExecutedActionMetadata, LogFile,
    OutputDirectory, OutputFile, OutputSymlink,
};
use nativelink_proto::com::github::trace_machina::nativelink::remote_execution::worker_api_server::WorkerApi;
use nativelink_proto::com::github::trace_machina::nativelink::remote_execution::{
    execute_result, update_for_worker, ExecuteResult, KeepAliveRequest, SupportedProperties,
};
use nativelink_proto::google::rpc::Status as ProtoStatus;
use nativelink_scheduler::api_worker_scheduler::ApiWorkerScheduler;
use nativelink_scheduler::platform_property_manager::PlatformPropertyManager;
use nativelink_scheduler::worker::ActionInfoWithProps;
use nativelink_scheduler::worker_scheduler::WorkerScheduler;
use nativelink_service::worker_api_server::{ConnectWorkerStream, NowFn, WorkerApiServer};
use nativelink_util::action_messages::{
    ActionInfo, ActionUniqueKey, ActionUniqueQualifier, OperationId, WorkerId,
};
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::operation_state_manager::{UpdateOperationType, WorkerStateManager};
use pretty_assertions::assert_eq;
use tokio::join;
use tokio::sync::{mpsc, Notify};
use tokio_stream::StreamExt;
use tonic::Request;

const BASE_NOW_S: u64 = 10;
const BASE_WORKER_TIMEOUT_S: u64 = 100;

#[derive(Debug)]
enum WorkerStateManagerCalls {
    UpdateOperation((OperationId, WorkerId, UpdateOperationType)),
}

#[derive(Debug)]
enum WorkerStateManagerReturns {
    UpdateOperation(Result<(), Error>),
}

#[derive(MetricsComponent)]
struct MockWorkerStateManager {
    rx_call: Arc<AsyncMutex<mpsc::UnboundedReceiver<WorkerStateManagerCalls>>>,
    tx_call: mpsc::UnboundedSender<WorkerStateManagerCalls>,
    rx_resp: Arc<AsyncMutex<mpsc::UnboundedReceiver<WorkerStateManagerReturns>>>,
    tx_resp: mpsc::UnboundedSender<WorkerStateManagerReturns>,
}

impl MockWorkerStateManager {
    pub fn new() -> Self {
        let (tx_call, rx_call) = mpsc::unbounded_channel();
        let (tx_resp, rx_resp) = mpsc::unbounded_channel();
        Self {
            rx_call: Arc::new(AsyncMutex::new(rx_call)),
            tx_call,
            rx_resp: Arc::new(AsyncMutex::new(rx_resp)),
            tx_resp,
        }
    }

    pub async fn expect_update_operation(
        &self,
        result: Result<(), Error>,
    ) -> (OperationId, WorkerId, UpdateOperationType) {
        let mut rx_call_lock = self.rx_call.lock().await;
        let recv = rx_call_lock.recv();
        let WorkerStateManagerCalls::UpdateOperation(req) =
            recv.await.expect("Could not receive msg in mpsc");
        self.tx_resp
            .send(WorkerStateManagerReturns::UpdateOperation(result))
            .expect("Could not send request to mpsc");
        req
    }
}

#[async_trait]
impl WorkerStateManager for MockWorkerStateManager {
    async fn update_operation(
        &self,
        operation_id: &OperationId,
        worker_id: &WorkerId,
        update: UpdateOperationType,
    ) -> Result<(), Error> {
        self.tx_call
            .send(WorkerStateManagerCalls::UpdateOperation((
                operation_id.clone(),
                *worker_id,
                update,
            )))
            .expect("Could not send request to mpsc");
        let mut rx_resp_lock = self.rx_resp.lock().await;
        match rx_resp_lock
            .recv()
            .await
            .expect("Could not receive msg in mpsc")
        {
            WorkerStateManagerReturns::UpdateOperation(result) => result,
        }
    }
}

struct TestContext {
    scheduler: Arc<ApiWorkerScheduler>,
    state_manager: Arc<MockWorkerStateManager>,
    worker_api_server: WorkerApiServer,
    connection_worker_stream: ConnectWorkerStream,
    worker_id: WorkerId,
}

#[allow(clippy::unnecessary_wraps)]
const fn static_now_fn() -> Result<Duration, Error> {
    Ok(Duration::from_secs(BASE_NOW_S))
}

async fn setup_api_server(worker_timeout: u64, now_fn: NowFn) -> Result<TestContext, Error> {
    const SCHEDULER_NAME: &str = "DUMMY_SCHEDULE_NAME";

    const UUID_SIZE: usize = 36;

    let platform_property_manager = Arc::new(PlatformPropertyManager::new(HashMap::new()));
    let tasks_or_worker_change_notify = Arc::new(Notify::new());
    let state_manager = Arc::new(MockWorkerStateManager::new());
    let scheduler = ApiWorkerScheduler::new(
        state_manager.clone(),
        platform_property_manager,
        WorkerAllocationStrategy::default(),
        tasks_or_worker_change_notify,
        worker_timeout,
    );

    let mut schedulers: HashMap<String, Arc<dyn WorkerScheduler>> = HashMap::new();
    schedulers.insert(SCHEDULER_NAME.to_string(), scheduler.clone());
    let worker_api_server = WorkerApiServer::new_with_now_fn(
        &WorkerApiConfig {
            scheduler: SCHEDULER_NAME.to_string(),
        },
        &schedulers,
        now_fn,
    )
    .err_tip(|| "Error creating WorkerApiServer")?;

    let supported_properties = SupportedProperties::default();
    let mut connection_worker_stream = worker_api_server
        .connect_worker(Request::new(supported_properties))
        .await?
        .into_inner();

    let maybe_first_message = connection_worker_stream.next().await;
    assert!(
        maybe_first_message.is_some(),
        "Expected first message from stream"
    );
    let first_update = maybe_first_message
        .unwrap()
        .err_tip(|| "Expected success result")?
        .update
        .err_tip(|| "Expected update field to be populated")?;
    let worker_id = match first_update {
        update_for_worker::Update::ConnectionResult(connection_result) => {
            connection_result.worker_id
        }
        other => unreachable!("Expected ConnectionResult, got {:?}", other),
    };

    assert_eq!(
        worker_id.len(),
        UUID_SIZE,
        "Worker ID should be 36 characters"
    );

    Ok(TestContext {
        scheduler,
        state_manager,
        worker_api_server,
        connection_worker_stream,
        worker_id: worker_id.try_into()?,
    })
}

#[nativelink_test]
pub async fn connect_worker_adds_worker_to_scheduler_test() -> Result<(), Box<dyn std::error::Error>>
{
    let test_context = setup_api_server(BASE_WORKER_TIMEOUT_S, Box::new(static_now_fn)).await?;

    let worker_exists = test_context
        .scheduler
        .contains_worker_for_test(&test_context.worker_id)
        .await;
    assert!(worker_exists, "Expected worker to exist in worker map");

    Ok(())
}

#[nativelink_test]
pub async fn server_times_out_workers_test() -> Result<(), Box<dyn std::error::Error>> {
    let test_context = setup_api_server(BASE_WORKER_TIMEOUT_S, Box::new(static_now_fn)).await?;

    let mut now_timestamp = BASE_NOW_S;
    {
        // Now change time to 1 second before timeout and ensure the worker is still in the pool.
        now_timestamp += BASE_WORKER_TIMEOUT_S - 1;
        test_context
            .scheduler
            .remove_timedout_workers(now_timestamp)
            .await?;
        let worker_exists = test_context
            .scheduler
            .contains_worker_for_test(&test_context.worker_id)
            .await;
        assert!(worker_exists, "Expected worker to exist in worker map");
    }
    {
        // Now add 1 second and our worker should have been evicted due to timeout.
        now_timestamp += 1;
        test_context
            .scheduler
            .remove_timedout_workers(now_timestamp)
            .await?;
        let worker_exists = test_context
            .scheduler
            .contains_worker_for_test(&test_context.worker_id)
            .await;
        assert!(!worker_exists, "Expected worker to not exist in map");
    }

    Ok(())
}

#[nativelink_test]
pub async fn server_does_not_timeout_if_keep_alive_test() -> Result<(), Box<dyn std::error::Error>>
{
    let now_timestamp = Arc::new(Mutex::new(BASE_NOW_S));
    let now_timestamp_clone = now_timestamp.clone();
    let add_and_return_timestamp = move |add_amount: u64| -> u64 {
        let mut locked_now_timestamp = now_timestamp.lock().unwrap();
        *locked_now_timestamp += add_amount;
        *locked_now_timestamp
    };

    let test_context = setup_api_server(
        BASE_WORKER_TIMEOUT_S,
        Box::new(move || Ok(Duration::from_secs(*now_timestamp_clone.lock().unwrap()))),
    )
    .await?;
    {
        // Now change time to 1 second before timeout and ensure the worker is still in the pool.
        let timestamp = add_and_return_timestamp(BASE_WORKER_TIMEOUT_S - 1);
        test_context
            .scheduler
            .remove_timedout_workers(timestamp)
            .await?;
        let worker_exists = test_context
            .scheduler
            .contains_worker_for_test(&test_context.worker_id)
            .await;
        assert!(worker_exists, "Expected worker to exist in worker map");
    }
    {
        // Now send keep alive.
        test_context
            .worker_api_server
            .keep_alive(Request::new(KeepAliveRequest {
                worker_id: test_context.worker_id.to_string(),
            }))
            .await
            .err_tip(|| "Error sending keep alive")?;
    }
    {
        // Now add 1 second and our worker should still exist in our map.
        let timestamp = add_and_return_timestamp(1);
        test_context
            .scheduler
            .remove_timedout_workers(timestamp)
            .await?;
        let worker_exists = test_context
            .scheduler
            .contains_worker_for_test(&test_context.worker_id)
            .await;
        assert!(worker_exists, "Expected worker to exist in map");
    }

    Ok(())
}

#[nativelink_test]
pub async fn worker_receives_keep_alive_request_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut test_context = setup_api_server(BASE_WORKER_TIMEOUT_S, Box::new(static_now_fn)).await?;

    // Send keep alive to client.
    test_context
        .scheduler
        .send_keep_alive_to_worker_for_test(&test_context.worker_id)
        .await
        .err_tip(|| "Could not send keep alive to worker")?;

    {
        // Read stream and ensure it was a keep alive message.
        let maybe_message = test_context.connection_worker_stream.next().await;
        assert!(
            maybe_message.is_some(),
            "Expected next message in stream to exist"
        );
        let update_message = maybe_message
            .unwrap()
            .err_tip(|| "Expected success result")?
            .update
            .err_tip(|| "Expected update field to be populated")?;
        assert_eq!(
            update_message,
            update_for_worker::Update::KeepAlive(()),
            "Expected KeepAlive message"
        );
    }

    Ok(())
}

#[nativelink_test]
pub async fn going_away_removes_worker_test() -> Result<(), Box<dyn std::error::Error>> {
    let test_context = setup_api_server(BASE_WORKER_TIMEOUT_S, Box::new(static_now_fn)).await?;

    let worker_exists = test_context
        .scheduler
        .contains_worker_for_test(&test_context.worker_id)
        .await;
    assert!(worker_exists, "Expected worker to exist in worker map");

    test_context
        .scheduler
        .remove_worker(&test_context.worker_id)
        .await
        .unwrap();

    let worker_exists = test_context
        .scheduler
        .contains_worker_for_test(&test_context.worker_id)
        .await;
    assert!(
        !worker_exists,
        "Expected worker to be removed from worker map"
    );

    Ok(())
}

fn make_system_time(time: u64) -> SystemTime {
    UNIX_EPOCH.checked_add(Duration::from_secs(time)).unwrap()
}

#[nativelink_test]
pub async fn execution_response_success_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut test_context = setup_api_server(BASE_WORKER_TIMEOUT_S, Box::new(static_now_fn)).await?;

    let action_digest = DigestInfo::new([7u8; 32], 123);
    let instance_name = "instance_name".to_string();

    let unique_qualifier = ActionUniqueQualifier::Uncachable(ActionUniqueKey {
        instance_name: instance_name.clone(),
        digest_function: DigestHasherFunc::Sha256,
        digest: action_digest,
    });
    let action_info = Arc::new(ActionInfo {
        command_digest: DigestInfo::new([0u8; 32], 0),
        input_root_digest: DigestInfo::new([0u8; 32], 0),
        timeout: Duration::MAX,
        platform_properties: HashMap::new(),
        priority: 0,
        load_timestamp: make_system_time(0),
        insert_timestamp: make_system_time(0),
        unique_qualifier,
    });
    let expected_operation_id = OperationId::default();

    let platform_properties = test_context
        .scheduler
        .get_platform_property_manager()
        .make_platform_properties(action_info.platform_properties.clone())
        .err_tip(|| "Failed to make platform properties in SimpleScheduler::do_try_match")?;

    test_context
        .scheduler
        .worker_notify_run_action(
            test_context.worker_id,
            expected_operation_id.clone(),
            ActionInfoWithProps {
                inner: action_info,
                platform_properties,
            },
        )
        .await
        .unwrap();

    let mut server_logs = HashMap::new();
    server_logs.insert(
        "log_name".to_string(),
        LogFile {
            digest: Some(DigestInfo::new([9u8; 32], 124).into()),
            human_readable: false, // We only support non-human readable.
        },
    );
    let execute_response = ExecuteResponse {
        result: Some(ProtoActionResult {
            output_files: vec![OutputFile {
                path: "some path1".to_string(),
                digest: Some(DigestInfo::new([8u8; 32], 124).into()),
                is_executable: true,
                contents: Bytes::default(), // We don't implement this.
                node_properties: None,
            }],
            output_file_symlinks: vec![OutputSymlink {
                path: "some path3".to_string(),
                target: "some target3".to_string(),
                node_properties: None,
            }],
            output_symlinks: vec![OutputSymlink {
                path: "some path3".to_string(),
                target: "some target3".to_string(),
                node_properties: None,
            }],
            output_directories: vec![OutputDirectory {
                path: "some path4".to_string(),
                tree_digest: Some(DigestInfo::new([12u8; 32], 124).into()),
                is_topologically_sorted: false,
            }],
            output_directory_symlinks: Vec::default(), // Bazel deprecated this.
            exit_code: 5,
            stdout_raw: Bytes::default(), // We don't implement this.
            stdout_digest: Some(DigestInfo::new([10u8; 32], 124).into()),
            stderr_raw: Bytes::default(), // We don't implement this.
            stderr_digest: Some(DigestInfo::new([11u8; 32], 124).into()),
            execution_metadata: Some(ExecutedActionMetadata {
                worker: test_context.worker_id.to_string(),
                queued_timestamp: Some(make_system_time(1).into()),
                worker_start_timestamp: Some(make_system_time(2).into()),
                worker_completed_timestamp: Some(make_system_time(3).into()),
                input_fetch_start_timestamp: Some(make_system_time(4).into()),
                input_fetch_completed_timestamp: Some(make_system_time(5).into()),
                execution_start_timestamp: Some(make_system_time(6).into()),
                execution_completed_timestamp: Some(make_system_time(7).into()),
                output_upload_start_timestamp: Some(make_system_time(8).into()),
                output_upload_completed_timestamp: Some(make_system_time(9).into()),
                virtual_execution_duration: Some(prost_types::Duration {
                    seconds: 1,
                    nanos: 0,
                }),
                auxiliary_metadata: vec![],
            }),
        }),
        cached_result: false,
        status: Some(ProtoStatus {
            code: 9,
            message: "foo".to_string(),
            details: Vec::default(),
        }),
        server_logs,
        message: "TODO(blaise.bruer) We should put a reference something like bb_browser"
            .to_string(),
    };
    let result = ExecuteResult {
        instance_name,
        worker_id: test_context.worker_id.to_string(),
        operation_id: expected_operation_id.to_string(),
        result: Some(execute_result::Result::ExecuteResponse(
            execute_response.clone(),
        )),
    };

    let update_for_worker = test_context
        .connection_worker_stream
        .next()
        .await
        .expect("Worker stream ended early")?
        .update
        .expect("Expected update field to be populated");
    let update_for_worker::Update::StartAction(start_execute) = update_for_worker else {
        panic!("Expected StartAction message");
    };
    assert_eq!(result.operation_id, start_execute.operation_id);

    {
        // Ensure our state manager got the same result as the server.
        let (execution_response_result, (operation_id, worker_id, client_given_update)) = join!(
            test_context
                .worker_api_server
                .execution_response(Request::new(result.clone())),
            test_context.state_manager.expect_update_operation(Ok(())),
        );
        execution_response_result.unwrap();

        assert_eq!(operation_id, expected_operation_id);
        assert_eq!(worker_id, test_context.worker_id);
        assert_eq!(
            client_given_update,
            UpdateOperationType::UpdateWithActionStage(execute_response.clone().try_into()?)
        );
        let UpdateOperationType::UpdateWithActionStage(client_given_state) = client_given_update
        else {
            unreachable!()
        };
        assert_eq!(execute_response, client_given_state.into());
    }
    Ok(())
}
