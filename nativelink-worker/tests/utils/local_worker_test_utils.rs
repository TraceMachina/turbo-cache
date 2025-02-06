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
use std::sync::Arc;

use async_lock::Mutex;
use bytes::Bytes;
use hyper::body::Frame;
use nativelink_config::cas_server::{EndpointConfig, LocalWorkerConfig, WorkerProperty};
use nativelink_error::Error;
use nativelink_proto::com::github::trace_machina::nativelink::remote_execution::{
    ConnectWorkerRequest, ExecuteResult, GoingAwayRequest, KeepAliveRequest, UpdateForWorker,
};
use nativelink_util::channel_body_for_tests::ChannelBody;
use nativelink_util::shutdown_guard::ShutdownGuard;
use nativelink_util::spawn;
use nativelink_util::task::JoinHandleDropGuard;
use nativelink_worker::local_worker::LocalWorker;
use nativelink_worker::worker_api_client_wrapper::WorkerApiClientTrait;
use tokio::sync::{broadcast, mpsc};
use tonic::Status;
use tonic::{
    codec::Codec, // Needed for .decoder().
    codec::CompressionEncoding,
    codec::ProstCodec,
    Response,
    Streaming,
};

use super::mock_running_actions_manager::MockRunningActionsManager;

/// Broadcast Channel Capacity
/// Note: The actual capacity may be greater than the provided capacity.
const BROADCAST_CAPACITY: usize = 1;

#[derive(Debug)]
enum WorkerClientApiCalls {
    ConnectWorker(ConnectWorkerRequest),
    ExecutionResponse(ExecuteResult),
}

#[derive(Debug)]
enum WorkerClientApiReturns {
    ConnectWorker(Result<Response<Streaming<UpdateForWorker>>, Status>),
    ExecutionResponse(Result<Response<()>, Status>),
}

#[derive(Clone)]
pub struct MockWorkerApiClient {
    rx_call: Arc<Mutex<mpsc::UnboundedReceiver<WorkerClientApiCalls>>>,
    tx_call: mpsc::UnboundedSender<WorkerClientApiCalls>,
    rx_resp: Arc<Mutex<mpsc::UnboundedReceiver<WorkerClientApiReturns>>>,
    tx_resp: mpsc::UnboundedSender<WorkerClientApiReturns>,
}

impl MockWorkerApiClient {
    pub fn new() -> Self {
        let (tx_call, rx_call) = mpsc::unbounded_channel();
        let (tx_resp, rx_resp) = mpsc::unbounded_channel();
        Self {
            rx_call: Arc::new(Mutex::new(rx_call)),
            tx_call,
            rx_resp: Arc::new(Mutex::new(rx_resp)),
            tx_resp,
        }
    }
}

impl Default for MockWorkerApiClient {
    fn default() -> Self {
        unreachable!("We don't test this functionality")
    }
}

impl MockWorkerApiClient {
    pub async fn expect_connect_worker(
        &mut self,
        result: Result<Response<Streaming<UpdateForWorker>>, Status>,
    ) -> ConnectWorkerRequest {
        let mut rx_call_lock = self.rx_call.lock().await;
        let req = match rx_call_lock
            .recv()
            .await
            .expect("Could not receive msg in mpsc")
        {
            WorkerClientApiCalls::ConnectWorker(req) => req,
            req @ WorkerClientApiCalls::ExecutionResponse(_) => {
                panic!("expect_connect_worker expected ConnectWorker, got : {req:?}")
            }
        };
        self.tx_resp
            .send(WorkerClientApiReturns::ConnectWorker(result))
            .expect("Could not send request to mpsc");
        req
    }

    pub async fn expect_execution_response(
        &mut self,
        result: Result<Response<()>, Status>,
    ) -> ExecuteResult {
        let mut rx_call_lock = self.rx_call.lock().await;
        let req = match rx_call_lock
            .recv()
            .await
            .expect("Could not receive msg in mpsc")
        {
            WorkerClientApiCalls::ExecutionResponse(req) => req,
            req @ WorkerClientApiCalls::ConnectWorker(_) => {
                panic!("expect_execution_response expected ExecutionResponse, got : {req:?}")
            }
        };
        self.tx_resp
            .send(WorkerClientApiReturns::ExecutionResponse(result))
            .expect("Could not send request to mpsc");
        req
    }
}

impl WorkerApiClientTrait for MockWorkerApiClient {
    async fn connect_worker(
        &mut self,
        request: ConnectWorkerRequest,
    ) -> Result<Response<Streaming<UpdateForWorker>>, Status> {
        self.tx_call
            .send(WorkerClientApiCalls::ConnectWorker(request))
            .expect("Could not send request to mpsc");
        let mut rx_resp_lock = self.rx_resp.lock().await;
        match rx_resp_lock
            .recv()
            .await
            .expect("Could not receive msg in mpsc")
        {
            WorkerClientApiReturns::ConnectWorker(result) => result,
            resp @ WorkerClientApiReturns::ExecutionResponse(_) => {
                panic!("connect_worker expected ConnectWorker response, received {resp:?}")
            }
        }
    }

    async fn keep_alive(&mut self, _request: KeepAliveRequest) -> Result<Response<()>, Status> {
        unreachable!();
    }

    async fn going_away(&mut self, _request: GoingAwayRequest) -> Result<Response<()>, Status> {
        unreachable!();
    }

    async fn execution_response(&mut self, request: ExecuteResult) -> Result<Response<()>, Status> {
        self.tx_call
            .send(WorkerClientApiCalls::ExecutionResponse(request))
            .expect("Could not send request to mpsc");
        let mut rx_resp_lock = self.rx_resp.lock().await;
        match rx_resp_lock
            .recv()
            .await
            .expect("Could not receive msg in mpsc")
        {
            WorkerClientApiReturns::ExecutionResponse(result) => result,
            resp @ WorkerClientApiReturns::ConnectWorker(_) => {
                panic!("execution_response expected ExecutionResponse response, received {resp:?}")
            }
        }
    }
}

pub fn setup_grpc_stream() -> (
    mpsc::Sender<Frame<Bytes>>,
    Response<Streaming<UpdateForWorker>>,
) {
    let (tx, body) = ChannelBody::new();
    let mut codec = ProstCodec::<UpdateForWorker, UpdateForWorker>::default();
    let stream =
        Streaming::new_request(codec.decoder(), body, Some(CompressionEncoding::Gzip), None);
    (tx, Response::new(stream))
}

pub async fn setup_local_worker_with_config(local_worker_config: LocalWorkerConfig) -> TestContext {
    let mock_worker_api_client = MockWorkerApiClient::new();
    let mock_worker_api_client_clone = mock_worker_api_client.clone();
    let actions_manager = Arc::new(MockRunningActionsManager::new());
    let worker = LocalWorker::new_with_connection_factory_and_actions_manager(
        Arc::new(local_worker_config),
        actions_manager.clone(),
        Box::new(move || {
            let mock_worker_api_client = mock_worker_api_client_clone.clone();
            Box::pin(async move { Ok(mock_worker_api_client) })
        }),
        Box::new(move |_| Box::pin(async move { /* No sleep */ })),
    );
    let (shutdown_tx_test, _) = broadcast::channel::<ShutdownGuard>(BROADCAST_CAPACITY);

    let drop_guard = spawn!("local_worker_spawn", async move {
        worker.run(shutdown_tx_test.subscribe()).await
    });

    let (tx_stream, streaming_response) = setup_grpc_stream();
    TestContext {
        client: mock_worker_api_client,
        actions_manager,

        maybe_streaming_response: Some(streaming_response),
        maybe_tx_stream: Some(tx_stream),

        _drop_guard: drop_guard,
    }
}

pub async fn setup_local_worker(
    platform_properties: HashMap<String, WorkerProperty>,
) -> TestContext {
    const ARBITRARY_LARGE_TIMEOUT: f32 = 10000.;
    let local_worker_config = LocalWorkerConfig {
        platform_properties,
        worker_api_endpoint: EndpointConfig {
            timeout: Some(ARBITRARY_LARGE_TIMEOUT),
            ..Default::default()
        },
        ..Default::default()
    };
    setup_local_worker_with_config(local_worker_config).await
}

pub struct TestContext {
    pub client: MockWorkerApiClient,
    pub actions_manager: Arc<MockRunningActionsManager>,

    pub maybe_streaming_response: Option<Response<Streaming<UpdateForWorker>>>,
    pub maybe_tx_stream: Option<mpsc::Sender<Frame<Bytes>>>,

    _drop_guard: JoinHandleDropGuard<Result<(), Error>>,
}
