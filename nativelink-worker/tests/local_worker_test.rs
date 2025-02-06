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
use std::env;
use std::ffi::OsString;
#[cfg(target_family = "unix")]
use std::fs::Permissions;
use std::io::Write;
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

mod utils {
    pub(crate) mod local_worker_test_utils;
    pub(crate) mod mock_running_actions_manager;
}

use hyper::body::Frame;
use nativelink_config::cas_server::{LocalWorkerConfig, WorkerProperty};
use nativelink_config::stores::{FastSlowSpec, FilesystemSpec, MemorySpec, StoreSpec};
use nativelink_error::{make_err, make_input_err, Code, Error};
use nativelink_macro::nativelink_test;
use nativelink_proto::build::bazel::remote::execution::v2::platform::Property;
use nativelink_proto::build::bazel::remote::execution::v2::Platform;
use nativelink_proto::com::github::trace_machina::nativelink::remote_execution::update_for_worker::Update;
use nativelink_proto::com::github::trace_machina::nativelink::remote_execution::{
    execute_result, ConnectWorkerRequest, ConnectionResult, ExecuteResult, KillOperationRequest,
    StartExecute, UpdateForWorker,
};
use nativelink_store::fast_slow_store::FastSlowStore;
use nativelink_store::filesystem_store::FilesystemStore;
use nativelink_store::memory_store::MemoryStore;
use nativelink_util::action_messages::{
    ActionInfo, ActionResult, ActionStage, ActionUniqueKey, ActionUniqueQualifier,
    ExecutionMetadata, OperationId,
};
use nativelink_util::common::{encode_stream_proto, fs, DigestInfo};
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::store_trait::Store;
use nativelink_worker::local_worker::new_local_worker;
use pretty_assertions::assert_eq;
use prost::Message;
use rand::{thread_rng, Rng};
use tokio::io::AsyncWriteExt;
use tonic::Response;
use utils::local_worker_test_utils::{
    setup_grpc_stream, setup_local_worker, setup_local_worker_with_config,
};
use utils::mock_running_actions_manager::MockRunningAction;

const INSTANCE_NAME: &str = "foo";

/// Get temporary path from either `TEST_TMPDIR` or best effort temp directory if
/// not set.
fn make_temp_path(data: &str) -> String {
    format!(
        "{}/{}/{}",
        env::var("TEST_TMPDIR").unwrap_or(env::temp_dir().to_str().unwrap().to_string()),
        thread_rng().gen::<u64>(),
        data
    )
}

#[cfg_attr(feature = "nix", ignore)]
#[nativelink_test]
async fn platform_properties_smoke_test() -> Result<(), Error> {
    let mut platform_properties = HashMap::new();
    platform_properties.insert(
        "foo".to_string(),
        WorkerProperty::values(vec!["bar1".to_string(), "bar2".to_string()]),
    );
    platform_properties.insert(
        "baz".to_string(),
        // Note: new lines will result in two entries for same key.
        #[cfg(target_family = "unix")]
        WorkerProperty::query_cmd("printf 'hello\ngoodbye'".to_string()),
        #[cfg(target_family = "windows")]
        WorkerProperty::query_cmd("cmd /C \"echo hello && echo goodbye\"".to_string()),
    );
    let mut test_context = setup_local_worker(platform_properties).await;
    let streaming_response = test_context.maybe_streaming_response.take().unwrap();

    // Now wait for our client to send `.connect_worker()` (which has our platform properties).
    let mut connect_worker_request = test_context
        .client
        .expect_connect_worker(Ok(streaming_response))
        .await;
    // It is undefined which order these will be returned in, so we sort it.
    connect_worker_request
        .properties
        .sort_by_key(Message::encode_to_vec);
    assert_eq!(
        connect_worker_request,
        ConnectWorkerRequest {
            worker_id_prefix: String::new(),
            properties: vec![
                Property {
                    name: "baz".to_string(),
                    value: "hello".to_string(),
                },
                Property {
                    name: "baz".to_string(),
                    value: "goodbye".to_string(),
                },
                Property {
                    name: "foo".to_string(),
                    value: "bar1".to_string(),
                },
                Property {
                    name: "foo".to_string(),
                    value: "bar2".to_string(),
                }
            ]
        }
    );

    Ok(())
}

#[nativelink_test]
async fn reconnect_on_server_disconnect_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut test_context = setup_local_worker(HashMap::new()).await;
    let streaming_response = test_context.maybe_streaming_response.take().unwrap();

    {
        // Ensure our worker connects and properties were sent.
        let props = test_context
            .client
            .expect_connect_worker(Ok(streaming_response))
            .await;
        assert_eq!(props, ConnectWorkerRequest::default());
    }

    // Disconnect our grpc stream.
    drop(test_context.maybe_tx_stream.take().unwrap());

    {
        // Client should try to auto reconnect and check our properties again.
        let (_, streaming_response) = setup_grpc_stream();
        let props = test_context
            .client
            .expect_connect_worker(Ok(streaming_response))
            .await;
        assert_eq!(props, ConnectWorkerRequest::default());
    }

    Ok(())
}

#[nativelink_test]
async fn kill_all_called_on_disconnect() -> Result<(), Box<dyn std::error::Error>> {
    let mut test_context = setup_local_worker(HashMap::new()).await;
    let streaming_response = test_context.maybe_streaming_response.take().unwrap();

    {
        // Ensure our worker connects and properties were sent.
        let props = test_context
            .client
            .expect_connect_worker(Ok(streaming_response))
            .await;
        assert_eq!(props, ConnectWorkerRequest::default());
    }

    // Handle registration (kill_all not called unless registered).
    let tx_stream = test_context.maybe_tx_stream.take().unwrap();
    {
        tx_stream
            .send(Frame::data(encode_stream_proto(&UpdateForWorker {
                update: Some(Update::ConnectionResult(ConnectionResult {
                    worker_id: "foobar".to_string(),
                })),
            })?))
            .await
            .map_err(|e| make_input_err!("Could not send : {:?}", e))?;
    }

    // Disconnect our grpc stream.
    drop(tx_stream);

    // Check that kill_all is called.
    test_context.actions_manager.expect_kill_all().await;

    Ok(())
}

#[nativelink_test]
async fn blake3_digest_function_registerd_properly() -> Result<(), Box<dyn std::error::Error>> {
    let mut test_context = setup_local_worker(HashMap::new()).await;
    let streaming_response = test_context.maybe_streaming_response.take().unwrap();

    {
        // Ensure our worker connects and properties were sent.
        let props = test_context
            .client
            .expect_connect_worker(Ok(streaming_response))
            .await;
        assert_eq!(props, ConnectWorkerRequest::default());
    }

    let expected_worker_id = "foobar".to_string();

    let tx_stream = test_context.maybe_tx_stream.take().unwrap();
    {
        // First initialize our worker by sending the response to the connection request.
        tx_stream
            .send(Frame::data(encode_stream_proto(&UpdateForWorker {
                update: Some(Update::ConnectionResult(ConnectionResult {
                    worker_id: expected_worker_id.clone(),
                })),
            })?))
            .await
            .map_err(|e| make_input_err!("Could not send : {:?}", e))?;
    }

    let action_digest = DigestInfo::new([3u8; 32], 10);
    let action_info = ActionInfo {
        command_digest: DigestInfo::new([1u8; 32], 10),
        input_root_digest: DigestInfo::new([2u8; 32], 10),
        timeout: Duration::from_secs(1),
        platform_properties: HashMap::new(),
        priority: 0,
        load_timestamp: SystemTime::UNIX_EPOCH,
        insert_timestamp: SystemTime::UNIX_EPOCH,
        unique_qualifier: ActionUniqueQualifier::Uncachable(ActionUniqueKey {
            instance_name: INSTANCE_NAME.to_string(),
            digest_function: DigestHasherFunc::Blake3,
            digest: action_digest,
        }),
    };

    {
        // Send execution request.
        tx_stream
            .send(Frame::data(encode_stream_proto(&UpdateForWorker {
                update: Some(Update::StartAction(StartExecute {
                    execute_request: Some((&action_info).into()),
                    operation_id: String::new(),
                    queued_timestamp: None,
                    platform: Some(Platform::default()),
                    worker_id: expected_worker_id.clone(),
                })),
            })?))
            .await
            .map_err(|e| make_input_err!("Could not send : {:?}", e))?;
    }
    let running_action = Arc::new(MockRunningAction::new());

    // Send and wait for response from create_and_add_action to RunningActionsManager.
    test_context
        .actions_manager
        .expect_create_and_add_action(Ok(running_action.clone()))
        .await;

    // Now the RunningAction needs to send a series of state updates. This shortcuts them
    // into a single call (shortcut for prepare, execute, upload, collect_results, cleanup).
    running_action
        .simple_expect_get_finished_result(Ok(ActionResult::default()))
        .await?;

    // Expect the action to be updated in the action cache.
    let (_stored_digest, _stored_result, digest_hasher) = test_context
        .actions_manager
        .expect_cache_action_result()
        .await;
    assert_eq!(digest_hasher, DigestHasherFunc::Blake3);

    Ok(())
}

#[nativelink_test]
async fn simple_worker_start_action_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut test_context = setup_local_worker(HashMap::new()).await;
    let streaming_response = test_context.maybe_streaming_response.take().unwrap();

    {
        // Ensure our worker connects and properties were sent.
        let props = test_context
            .client
            .expect_connect_worker(Ok(streaming_response))
            .await;
        assert_eq!(props, ConnectWorkerRequest::default());
    }

    let expected_worker_id = "foobar".to_string();

    let tx_stream = test_context.maybe_tx_stream.take().unwrap();
    {
        // First initialize our worker by sending the response to the connection request.
        tx_stream
            .send(Frame::data(encode_stream_proto(&UpdateForWorker {
                update: Some(Update::ConnectionResult(ConnectionResult {
                    worker_id: expected_worker_id.clone(),
                })),
            })?))
            .await
            .map_err(|e| make_input_err!("Could not send : {:?}", e))?;
    }

    let action_digest = DigestInfo::new([3u8; 32], 10);
    let action_info = ActionInfo {
        command_digest: DigestInfo::new([1u8; 32], 10),
        input_root_digest: DigestInfo::new([2u8; 32], 10),
        timeout: Duration::from_secs(1),
        platform_properties: HashMap::new(),
        priority: 0,
        load_timestamp: SystemTime::UNIX_EPOCH,
        insert_timestamp: SystemTime::UNIX_EPOCH,
        unique_qualifier: ActionUniqueQualifier::Uncachable(ActionUniqueKey {
            instance_name: INSTANCE_NAME.to_string(),
            digest_function: DigestHasherFunc::Sha256,
            digest: action_digest,
        }),
    };

    {
        // Send execution request.
        tx_stream
            .send(Frame::data(encode_stream_proto(&UpdateForWorker {
                update: Some(Update::StartAction(StartExecute {
                    execute_request: Some((&action_info).into()),
                    operation_id: String::new(),
                    queued_timestamp: None,
                    platform: Some(Platform::default()),
                    worker_id: expected_worker_id.clone(),
                })),
            })?))
            .await
            .map_err(|e| make_input_err!("Could not send : {:?}", e))?;
    }
    let action_result = ActionResult {
        output_files: vec![],
        output_folders: vec![],
        output_file_symlinks: vec![],
        output_directory_symlinks: vec![],
        exit_code: 5,
        stdout_digest: DigestInfo::new([21u8; 32], 10),
        stderr_digest: DigestInfo::new([22u8; 32], 10),
        execution_metadata: ExecutionMetadata {
            worker: expected_worker_id.clone(),
            queued_timestamp: SystemTime::UNIX_EPOCH,
            worker_start_timestamp: SystemTime::UNIX_EPOCH,
            worker_completed_timestamp: SystemTime::UNIX_EPOCH,
            input_fetch_start_timestamp: SystemTime::UNIX_EPOCH,
            input_fetch_completed_timestamp: SystemTime::UNIX_EPOCH,
            execution_start_timestamp: SystemTime::UNIX_EPOCH,
            execution_completed_timestamp: SystemTime::UNIX_EPOCH,
            output_upload_start_timestamp: SystemTime::UNIX_EPOCH,
            output_upload_completed_timestamp: SystemTime::UNIX_EPOCH,
        },
        server_logs: HashMap::new(),
        error: None,
        message: String::new(),
    };
    let running_action = Arc::new(MockRunningAction::new());

    // Send and wait for response from create_and_add_action to RunningActionsManager.
    test_context
        .actions_manager
        .expect_create_and_add_action(Ok(running_action.clone()))
        .await;

    // Now the RunningAction needs to send a series of state updates. This shortcuts them
    // into a single call (shortcut for prepare, execute, upload, collect_results, cleanup).
    running_action
        .simple_expect_get_finished_result(Ok(action_result.clone()))
        .await?;

    // Expect the action to be updated in the action cache.
    let (stored_digest, stored_result, digest_hasher) = test_context
        .actions_manager
        .expect_cache_action_result()
        .await;
    assert_eq!(stored_digest, action_digest);
    assert_eq!(stored_result, action_result.clone());
    assert_eq!(digest_hasher, DigestHasherFunc::Sha256);

    // Now our client should be notified that our runner finished.
    let execution_response = test_context
        .client
        .expect_execution_response(Ok(Response::new(())))
        .await;

    // Now ensure the final results match our expectations.
    assert_eq!(
        execution_response,
        ExecuteResult {
            worker_id: expected_worker_id,
            instance_name: INSTANCE_NAME.to_string(),
            operation_id: String::new(),
            result: Some(execute_result::Result::ExecuteResponse(
                ActionStage::Completed(action_result).into()
            )),
        }
    );

    Ok(())
}

#[nativelink_test]
async fn new_local_worker_creates_work_directory_test() -> Result<(), Box<dyn std::error::Error>> {
    let cas_store = Store::new(FastSlowStore::new(
        &FastSlowSpec {
            // Note: These are not needed for this test, so we put dummy memory stores here.
            fast: StoreSpec::memory(MemorySpec::default()),
            slow: StoreSpec::memory(MemorySpec::default()),
        },
        Store::new(
            <FilesystemStore>::new(&FilesystemSpec {
                content_path: make_temp_path("content_path"),
                temp_path: make_temp_path("temp_path"),
                ..Default::default()
            })
            .await?,
        ),
        Store::new(MemoryStore::new(&MemorySpec::default())),
    ));
    let ac_store = Store::new(MemoryStore::new(&MemorySpec::default()));
    let work_directory = make_temp_path("foo");
    new_local_worker(
        Arc::new(LocalWorkerConfig {
            work_directory: work_directory.clone(),
            ..Default::default()
        }),
        cas_store.clone(),
        Some(ac_store),
        cas_store,
    )
    .await?;

    assert!(
        fs::metadata(work_directory).await.is_ok(),
        "Expected work_directory to be created"
    );

    Ok(())
}

#[nativelink_test]
async fn new_local_worker_removes_work_directory_before_start_test(
) -> Result<(), Box<dyn std::error::Error>> {
    let cas_store = Store::new(FastSlowStore::new(
        &FastSlowSpec {
            // Note: These are not needed for this test, so we put dummy memory stores here.
            fast: StoreSpec::memory(MemorySpec::default()),
            slow: StoreSpec::memory(MemorySpec::default()),
        },
        Store::new(
            <FilesystemStore>::new(&FilesystemSpec {
                content_path: make_temp_path("content_path"),
                temp_path: make_temp_path("temp_path"),
                ..Default::default()
            })
            .await?,
        ),
        Store::new(MemoryStore::new(&MemorySpec::default())),
    ));
    let ac_store = Store::new(MemoryStore::new(&MemorySpec::default()));
    let work_directory = make_temp_path("foo");
    fs::create_dir_all(format!("{}/{}", work_directory, "another_dir")).await?;
    let mut file =
        fs::create_file(OsString::from(format!("{}/{}", work_directory, "foo.txt"))).await?;
    file.as_writer().await?.write_all(b"Hello, world!").await?;
    file.as_writer().await?.as_mut().sync_all().await?;
    drop(file);
    new_local_worker(
        Arc::new(LocalWorkerConfig {
            work_directory: work_directory.clone(),
            ..Default::default()
        }),
        cas_store.clone(),
        Some(ac_store),
        cas_store,
    )
    .await?;

    let work_directory_path_buf = PathBuf::from(work_directory);

    assert!(
        work_directory_path_buf.read_dir()?.next().is_none(),
        "Expected work_directory to have removed all files and to be empty"
    );

    Ok(())
}

#[nativelink_test]
async fn experimental_precondition_script_fails() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_family = "unix")]
    const EXPECTED_MSG: &str = "Preconditions script returned status exit status: 1 - ";
    #[cfg(target_family = "windows")]
    const EXPECTED_MSG: &str = "Preconditions script returned status exit code: 1 - ";

    let temp_path = make_temp_path("scripts");
    fs::create_dir_all(temp_path.clone()).await?;
    #[cfg(target_family = "unix")]
    let precondition_script = {
        let precondition_script = format!("{temp_path}/precondition.sh");
        // We use std::fs::File here because we sometimes get strange bugs here
        // that result in: "Text file busy (os error 26)" if it is an executeable.
        // It is likley because somewhere the file descriotor does not get closed
        // in tokio's async context.
        let mut file = std::fs::File::create(OsString::from(&precondition_script))?;
        file.write_all(b"#!/bin/sh\nexit 1\n")?;
        file.set_permissions(Permissions::from_mode(0o777))?;
        file.sync_all()?;
        drop(file);
        precondition_script
    };
    #[cfg(target_family = "windows")]
    let precondition_script = {
        let precondition_script = format!("{}/precondition.bat", temp_path);
        let mut file = std::fs::File::create(OsString::from(&precondition_script))?;
        file.write_all(b"@echo off\r\nexit 1")?;
        file.sync_all()?;
        drop(file);
        precondition_script
    };
    // TODO(#527) Sleep to reduce flakey chances.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let local_worker_config = LocalWorkerConfig {
        experimental_precondition_script: Some(precondition_script),
        ..Default::default()
    };

    let mut test_context = setup_local_worker_with_config(local_worker_config).await;
    let streaming_response = test_context.maybe_streaming_response.take().unwrap();

    {
        // Ensure our worker connects and properties were sent.
        let props = test_context
            .client
            .expect_connect_worker(Ok(streaming_response))
            .await;
        assert_eq!(props, ConnectWorkerRequest::default());
    }

    let expected_worker_id = "foobar".to_string();

    let tx_stream = test_context.maybe_tx_stream.take().unwrap();
    {
        // First initialize our worker by sending the response to the connection request.
        tx_stream
            .send(Frame::data(encode_stream_proto(&UpdateForWorker {
                update: Some(Update::ConnectionResult(ConnectionResult {
                    worker_id: expected_worker_id.clone(),
                })),
            })?))
            .await
            .map_err(|e| make_input_err!("Could not send : {:?}", e))?;
    }

    let action_digest = DigestInfo::new([3u8; 32], 10);
    let action_info = ActionInfo {
        command_digest: DigestInfo::new([1u8; 32], 10),
        input_root_digest: DigestInfo::new([2u8; 32], 10),
        timeout: Duration::from_secs(1),
        platform_properties: HashMap::new(),
        priority: 0,
        load_timestamp: SystemTime::UNIX_EPOCH,
        insert_timestamp: SystemTime::UNIX_EPOCH,
        unique_qualifier: ActionUniqueQualifier::Uncachable(ActionUniqueKey {
            instance_name: INSTANCE_NAME.to_string(),
            digest_function: DigestHasherFunc::Sha256,
            digest: action_digest,
        }),
    };

    {
        // Send execution request.
        tx_stream
            .send(Frame::data(encode_stream_proto(&UpdateForWorker {
                update: Some(Update::StartAction(StartExecute {
                    execute_request: Some((&action_info).into()),
                    operation_id: String::new(),
                    queued_timestamp: None,
                    platform: Some(Platform::default()),
                    worker_id: expected_worker_id.clone(),
                })),
            })?))
            .await
            .map_err(|e| make_input_err!("Could not send : {:?}", e))?;
    }

    // Now our client should be notified that our runner finished.
    let execution_response = test_context
        .client
        .expect_execution_response(Ok(Response::new(())))
        .await;

    // Now ensure the final results match our expectations.
    assert_eq!(
        execution_response,
        ExecuteResult {
            worker_id: expected_worker_id,
            instance_name: INSTANCE_NAME.to_string(),
            operation_id: String::new(),
            result: Some(execute_result::Result::InternalError(
                make_err!(Code::ResourceExhausted, "{}", EXPECTED_MSG,).into()
            )),
        }
    );

    Ok(())
}

#[nativelink_test]
async fn kill_action_request_kills_action() -> Result<(), Box<dyn std::error::Error>> {
    let mut test_context = setup_local_worker(HashMap::new()).await;

    let streaming_response = test_context.maybe_streaming_response.take().unwrap();

    {
        // Ensure our worker connects and properties were sent.
        let props = test_context
            .client
            .expect_connect_worker(Ok(streaming_response))
            .await;
        assert_eq!(props, ConnectWorkerRequest::default());
    }

    let expected_worker_id = "foobar".to_string();

    // Handle registration (kill_all not called unless registered).
    let tx_stream = test_context.maybe_tx_stream.take().unwrap();
    {
        tx_stream
            .send(Frame::data(encode_stream_proto(&UpdateForWorker {
                update: Some(Update::ConnectionResult(ConnectionResult {
                    worker_id: expected_worker_id.clone(),
                })),
            })?))
            .await
            .map_err(|e| make_input_err!("Could not send : {:?}", e))?;
    }

    let action_digest = DigestInfo::new([3u8; 32], 10);
    let action_info = ActionInfo {
        command_digest: DigestInfo::new([1u8; 32], 10),
        input_root_digest: DigestInfo::new([2u8; 32], 10),
        timeout: Duration::from_secs(1),
        platform_properties: HashMap::new(),
        priority: 0,
        load_timestamp: SystemTime::UNIX_EPOCH,
        insert_timestamp: SystemTime::UNIX_EPOCH,
        unique_qualifier: ActionUniqueQualifier::Uncachable(ActionUniqueKey {
            instance_name: INSTANCE_NAME.to_string(),
            digest_function: DigestHasherFunc::Blake3,
            digest: action_digest,
        }),
    };

    let operation_id = OperationId::default();
    {
        // Send execution request.
        tx_stream
            .send(Frame::data(encode_stream_proto(&UpdateForWorker {
                update: Some(Update::StartAction(StartExecute {
                    execute_request: Some((&action_info).into()),
                    operation_id: operation_id.to_string(),
                    queued_timestamp: None,
                    platform: Some(Platform::default()),
                    worker_id: expected_worker_id.clone(),
                })),
            })?))
            .await
            .map_err(|e| make_input_err!("Could not send : {:?}", e))?;
    }
    let running_action = Arc::new(MockRunningAction::new());

    // Send and wait for response from create_and_add_action to RunningActionsManager.
    test_context
        .actions_manager
        .expect_create_and_add_action(Ok(running_action.clone()))
        .await;

    {
        // Send kill request.
        tx_stream
            .send(Frame::data(encode_stream_proto(&UpdateForWorker {
                update: Some(Update::KillOperationRequest(KillOperationRequest {
                    operation_id: operation_id.to_string(),
                })),
            })?))
            .await
            .map_err(|e| make_input_err!("Could not send : {:?}", e))?;
    }

    let killed_operation_id = test_context.actions_manager.expect_kill_operation().await;

    // Make sure that the killed action is the one we intended
    assert_eq!(killed_operation_id, operation_id);

    Ok(())
}
