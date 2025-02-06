// gcs_client/grpc_client.rs
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures::Stream;
use googleapis_tonic_google_storage_v2::google::storage::v2::storage_client::StorageClient;
use googleapis_tonic_google_storage_v2::google::storage::v2::{
    BidiWriteObjectRequest, BidiWriteObjectResponse, ReadObjectRequest, ReadObjectResponse,
    StartResumableWriteRequest, StartResumableWriteResponse, WriteObjectRequest,
    WriteObjectResponse,
};
use nativelink_error::{make_err, Code, Error};
use tonic::transport::Channel;
use tonic::{Request, Response, Status, Streaming};

pub type WriteObjectStream = Pin<Box<dyn Stream<Item = WriteObjectRequest> + Send + 'static>>;
pub type BidiWriteObjectStream =
    Pin<Box<dyn Stream<Item = BidiWriteObjectRequest> + Send + 'static>>;

#[async_trait::async_trait]
pub trait GcsGrpcClient: Send + Sync + 'static {
    async fn read_object(
        &mut self,
        request: Request<ReadObjectRequest>,
    ) -> Result<Response<Streaming<ReadObjectResponse>>, Status>;

    async fn write_object(
        &mut self,
        request: Request<WriteObjectStream>,
    ) -> Result<Response<WriteObjectResponse>, Status>;

    async fn start_resumable_write(
        &mut self,
        request: Request<StartResumableWriteRequest>,
    ) -> Result<Response<StartResumableWriteResponse>, Status>;

    async fn bidi_write_object(
        &mut self,
        request: Request<BidiWriteObjectStream>,
    ) -> Result<Response<Streaming<BidiWriteObjectResponse>>, Status>;
}

#[async_trait::async_trait]
impl GcsGrpcClient for StorageClient<Channel> {
    async fn read_object(
        &mut self,
        request: Request<ReadObjectRequest>,
    ) -> Result<Response<Streaming<ReadObjectResponse>>, Status> {
        StorageClient::read_object(self, request).await
    }

    async fn write_object(
        &mut self,
        request: Request<WriteObjectStream>,
    ) -> Result<Response<WriteObjectResponse>, Status> {
        let fut: Pin<
            Box<dyn Future<Output = Result<Response<WriteObjectResponse>, Status>> + Send>,
        > = Box::pin(StorageClient::write_object(self, request));
        fut.await
    }

    async fn start_resumable_write(
        &mut self,
        request: Request<StartResumableWriteRequest>,
    ) -> Result<Response<StartResumableWriteResponse>, Status> {
        StorageClient::start_resumable_write(self, request).await
    }

    async fn bidi_write_object(
        &mut self,
        request: Request<BidiWriteObjectStream>,
    ) -> Result<Response<Streaming<BidiWriteObjectResponse>>, Status> {
        let fut: Pin<
            Box<
                dyn Future<Output = Result<Response<Streaming<BidiWriteObjectResponse>>, Status>>
                    + Send,
            >,
        > = Box::pin(StorageClient::bidi_write_object(self, request));
        fut.await
    }
}

// Client wrapper for connection management and configuration
pub struct GcsGrpcClientWrapper {
    inner: Arc<tokio::sync::Mutex<dyn GcsGrpcClient>>,
}

impl GcsGrpcClientWrapper {
    pub fn new<T: GcsGrpcClient + 'static>(client: T) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(client)),
        }
    }

    pub async fn handle_request<T>(
        &mut self,
        operation: impl FnOnce(
            &mut dyn GcsGrpcClient,
        )
            -> Pin<Box<dyn Future<Output = Result<Response<T>, Status>> + Send + '_>>,
    ) -> Result<Response<T>, Error> {
        let mut guard = self.inner.lock().await;
        operation(&mut *guard).await.map_err(|e| match e.code() {
            tonic::Code::NotFound => make_err!(Code::NotFound, "Resource not found: {}", e),
            _ => make_err!(Code::Unavailable, "Operation failed: {}", e),
        })
    }
}
