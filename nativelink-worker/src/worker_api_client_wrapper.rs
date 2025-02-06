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

use std::future::Future;

use nativelink_proto::com::github::trace_machina::nativelink::remote_execution::worker_api_client::WorkerApiClient;
use nativelink_proto::com::github::trace_machina::nativelink::remote_execution::{
    ConnectWorkerRequest, ExecuteResult, GoingAwayRequest, KeepAliveRequest, UpdateForWorker,
};
use tonic::codec::Streaming;
use tonic::transport::Channel;
use tonic::{Response, Status};

/// This is used in order to allow unit tests to intercept these calls. This should always match
/// the API of `WorkerApiClient` defined in the `worker_api.proto` file.
pub trait WorkerApiClientTrait: Clone + Sync + Send + Sized + Unpin {
    fn connect_worker(
        &mut self,
        request: ConnectWorkerRequest,
    ) -> impl Future<Output = Result<Response<Streaming<UpdateForWorker>>, Status>> + Send;

    fn keep_alive(
        &mut self,
        request: KeepAliveRequest,
    ) -> impl Future<Output = Result<Response<()>, Status>> + Send;

    fn going_away(
        &mut self,
        request: GoingAwayRequest,
    ) -> impl Future<Output = Result<Response<()>, Status>> + Send;

    fn execution_response(
        &mut self,
        request: ExecuteResult,
    ) -> impl Future<Output = Result<Response<()>, Status>> + Send;
}

#[derive(Clone)]
pub struct WorkerApiClientWrapper {
    inner: WorkerApiClient<Channel>,
}

impl From<WorkerApiClient<Channel>> for WorkerApiClientWrapper {
    fn from(other: WorkerApiClient<Channel>) -> Self {
        Self { inner: other }
    }
}

impl WorkerApiClientTrait for WorkerApiClientWrapper {
    async fn connect_worker(
        &mut self,
        request: ConnectWorkerRequest,
    ) -> Result<Response<Streaming<UpdateForWorker>>, Status> {
        self.inner.connect_worker(request).await
    }

    async fn keep_alive(&mut self, request: KeepAliveRequest) -> Result<Response<()>, Status> {
        self.inner.keep_alive(request).await
    }

    async fn going_away(&mut self, request: GoingAwayRequest) -> Result<Response<()>, Status> {
        self.inner.going_away(request).await
    }

    async fn execution_response(&mut self, request: ExecuteResult) -> Result<Response<()>, Status> {
        self.inner.execution_response(request).await
    }
}
