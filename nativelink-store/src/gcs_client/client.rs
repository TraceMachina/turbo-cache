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

use std::sync::Arc;
use std::time::Duration;

use futures::{StreamExt, TryStreamExt};
use googleapis_tonic_google_storage_v2::google::storage::v2::storage_client::StorageClient;
use googleapis_tonic_google_storage_v2::google::storage::v2::{
    bidi_write_object_request, write_object_request, BidiWriteObjectRequest, ChecksummedData,
    Object, ReadObjectRequest, StartResumableWriteRequest, WriteObjectRequest, WriteObjectSpec,
};
use nativelink_config::stores::GcsSpec;
use nativelink_error::{make_err, Code, Error, ResultExt};
use nativelink_util::buf_channel::{make_buf_channel_pair, DropCloserReadHalf};
use nativelink_util::retry::{Retrier, RetryResult};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::transport::{Channel, ClientTlsConfig};
use tonic::Request;

use crate::gcs_client::auth::GcsAuth;
use crate::gcs_client::grpc_client::{
    BidiWriteObjectStream, GcsGrpcClient, GcsGrpcClientWrapper, WriteObjectStream,
};

const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1000; // < 4 MiB

#[derive(Clone)]
pub struct ObjectPath {
    bucket: String,
    path: String,
}

async fn create_channel(spec: &GcsSpec) -> Result<Channel, Error> {
    let endpoint = match &spec.endpoint {
        Some(endpoint) => {
            let prefix = if spec.insecure_allow_http {
                "http://"
            } else {
                "https://"
            };
            format!("{prefix}{endpoint}")
        }
        None => std::env::var("GOOGLE_STORAGE_ENDPOINT")
            .unwrap_or_else(|_| "https://storage.googleapis.com".to_string()),
    };

    let mut channel = Channel::from_shared(endpoint)
        .map_err(|e| make_err!(Code::InvalidArgument, "Invalid GCS endpoint: {e:?}"))?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .tcp_nodelay(true);

    if !spec.disable_http2 {
        channel = channel
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(Duration::from_secs(30));
    }

    if !spec.insecure_allow_http {
        channel = channel
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .map_err(|e| make_err!(Code::InvalidArgument, "Failed to configure TLS: {e:?}"))?;
    }

    channel
        .connect()
        .await
        .map_err(|e| make_err!(Code::Unavailable, "Failed to connect to GCS: {e:?}"))
}

impl ObjectPath {
    pub fn new(bucket: String, path: &str) -> Self {
        let normalized_path = path.replace('\\', "/").trim_start_matches('/').to_string();
        Self {
            bucket,
            path: normalized_path,
        }
    }

    pub fn get_formatted_bucket(&self) -> String {
        format!("projects/_/buckets/{}", self.bucket)
    }
}

#[derive(Clone)]
pub struct GcsClient {
    client: Arc<RwLock<GcsGrpcClientWrapper>>,
    auth: Arc<GcsAuth>,
    retrier: Arc<Retrier>,
}

impl GcsClient {
    pub async fn new_with_client(
        client: impl GcsGrpcClient + 'static,
        spec: &GcsSpec,
        jitter_fn: Arc<dyn Fn(Duration) -> Duration + Send + Sync>,
    ) -> Result<Self, Error> {
        Ok(Self {
            client: Arc::new(RwLock::new(GcsGrpcClientWrapper::new(client))),
            auth: Arc::new(GcsAuth::new(spec).await?),
            retrier: Arc::new(Retrier::new(
                Arc::new(|duration| Box::pin(sleep(duration))),
                jitter_fn,
                spec.retry.clone(),
            )),
        })
    }

    pub async fn new(
        spec: &GcsSpec,
        jitter_fn: Arc<dyn Fn(Duration) -> Duration + Send + Sync>,
    ) -> Result<Self, Error> {
        let channel = create_channel(spec).await?;
        let storage_client = StorageClient::new(channel);
        Self::new_with_client(storage_client, spec, jitter_fn).await
    }

    async fn add_auth_and_common_headers(
        &self,
        metadata: &mut MetadataMap,
        object: ObjectPath,
    ) -> Result<(), Error> {
        // Add authorization header
        let token = self.auth.get_valid_token().await?;
        metadata.insert(
            "authorization",
            MetadataValue::try_from(&format!("Bearer {token}")).unwrap(),
        );

        // Add bucket parameter. This is required for all requests
        let bucket = object.get_formatted_bucket();
        let encoded_bucket = urlencoding::encode(&bucket);
        let params = format!("bucket={encoded_bucket}");

        metadata.insert(
            "x-goog-request-params",
            MetadataValue::try_from(&params).unwrap(),
        );

        Ok(())
    }

    async fn prepare_request<T>(&self, request: T, object: ObjectPath) -> Request<T> {
        let mut request = Request::new(request);
        self.add_auth_and_common_headers(request.metadata_mut(), object)
            .await
            .expect("Failed to add headers");
        request
    }

    fn create_write_spec(&self, object: &ObjectPath, size: i64) -> WriteObjectSpec {
        WriteObjectSpec {
            resource: Some(Object {
                name: object.path.clone(),
                bucket: object.get_formatted_bucket(),
                size,
                content_type: "application/octet-stream".to_string(),
                ..Default::default()
            }),
            object_size: Some(size),
            ..Default::default()
        }
    }

    pub async fn simple_upload(
        &self,
        object: ObjectPath,
        reader: DropCloserReadHalf,
        size: i64,
    ) -> Result<(), Error> {
        let retrier = self.retrier.clone();
        let client = self.client.clone();
        let object_clone = object.clone();
        let self_clone = self.clone();
        let write_spec = self.create_write_spec(&object, size);

        // Create a stream that will yield our operation result
        let operation_stream = futures::stream::unfold(
            (client, object_clone, self_clone, write_spec, reader),
            move |(client, object, self_ref, write_spec, mut reader)| {
                async move {
                    let (mut tx, mut rx) = make_buf_channel_pair();

                    let attempt_result = async {
                        let (upload_res, bind_res) = tokio::join!(
                            async {
                                let mut client_guard = client.write().await;
                                let mut buffer = Vec::with_capacity(size as usize);
                                while let Ok(Some(chunk)) = rx.try_next().await {
                                    buffer.extend_from_slice(&chunk);
                                }
                                let crc32c = crc32c::crc32c(&buffer);

                                let init_request = WriteObjectRequest {
                                    first_message: Some(
                                        write_object_request::FirstMessage::WriteObjectSpec(
                                            write_spec.clone(),
                                        ),
                                    ),
                                    write_offset: 0,
                                    data: None,
                                    finish_write: false,
                                    ..Default::default()
                                };

                                let data_request = WriteObjectRequest {
                                    first_message: None,
                                    write_offset: 0,
                                    data: Some(write_object_request::Data::ChecksummedData(
                                        ChecksummedData {
                                            content: buffer,
                                            crc32c: Some(crc32c),
                                        },
                                    )),
                                    finish_write: true,
                                    ..Default::default()
                                };

                                let request_stream = Box::pin(futures::stream::iter(vec![
                                    init_request,
                                    data_request,
                                ]))
                                    as WriteObjectStream;
                                let mut request = Request::new(request_stream);

                                self_ref
                                    .add_auth_and_common_headers(
                                        request.metadata_mut(),
                                        object.clone(),
                                    )
                                    .await?;

                                client_guard
                                    .handle_request(|client| Box::pin(client.write_object(request)))
                                    .await
                            },
                            async { tx.bind_buffered(&mut reader).await }
                        );

                        match (upload_res, bind_res) {
                            (Ok(_), Ok(())) => Ok(()),
                            (Err(e), _) | (_, Err(e)) => Err(e),
                        }
                    }
                    .await;

                    // Return both the result and the state for potential next retry
                    Some((
                        RetryResult::Ok(attempt_result),
                        (client, object, self_ref, write_spec, reader),
                    ))
                }
            },
        );

        retrier.retry(operation_stream).await?
    }

    pub async fn resumable_upload(
        &self,
        object: ObjectPath,
        reader: DropCloserReadHalf,
        size: i64,
    ) -> Result<(), Error> {
        let retrier = self.retrier.clone();
        let client = self.client.clone();
        let object_clone = object.clone();
        let self_clone = self.clone();
        let write_spec = self.create_write_spec(&object, size);

        let operation_stream = futures::stream::unfold(
            (client, object_clone, self_clone, write_spec, reader),
            move |(client, object, self_ref, write_spec, mut reader)| async move {
                let attempt_result = async {
                    let mut client_guard = client.write().await;
                    let start_request = StartResumableWriteRequest {
                        write_object_spec: Some(write_spec.clone()),
                        common_object_request_params: None,
                        object_checksums: None,
                    };

                    let request = self_ref
                        .prepare_request(start_request, object.clone())
                        .await;
                    let response = client_guard
                        .handle_request(|client| Box::pin(client.start_resumable_write(request)))
                        .await?;

                    let upload_id = response.into_inner().upload_id;

                    let mut requests = Vec::new();
                    requests.push(BidiWriteObjectRequest {
                        first_message: Some(bidi_write_object_request::FirstMessage::UploadId(
                            upload_id,
                        )),
                        write_offset: 0,
                        finish_write: false,
                        data: None,
                        ..Default::default()
                    });

                    let mut offset = 0;
                    while offset < size {
                        let chunk_size = std::cmp::min(MAX_CHUNK_SIZE, (size - offset) as usize);

                        let chunk = reader
                            .consume(Some(chunk_size))
                            .await
                            .err_tip(|| "Failed to read chunk")?;

                        if chunk.is_empty() {
                            break;
                        }

                        let chunk_len = chunk.len();
                        let crc32c = crc32c::crc32c(&chunk);
                        let is_last = offset + (chunk_len as i64) >= size;

                        requests.push(BidiWriteObjectRequest {
                            first_message: None,
                            write_offset: offset,
                            data: Some(bidi_write_object_request::Data::ChecksummedData(
                                ChecksummedData {
                                    content: chunk.to_vec(),
                                    crc32c: Some(crc32c),
                                },
                            )),
                            finish_write: is_last,
                            ..Default::default()
                        });

                        offset += chunk_len as i64;
                    }

                    let request_stream =
                        Box::pin(futures::stream::iter(requests)) as BidiWriteObjectStream;
                    let mut request = Request::new(request_stream);

                    self_ref
                        .add_auth_and_common_headers(request.metadata_mut(), object.clone())
                        .await?;

                    client_guard
                        .handle_request(|client| Box::pin(client.bidi_write_object(request)))
                        .await?;

                    Ok(())
                }
                .await;

                Some((
                    RetryResult::Ok(attempt_result),
                    (client, object, self_ref, write_spec, reader),
                ))
            },
        );

        retrier.retry(operation_stream).await?
    }

    async fn read_object(
        &self,
        object: ObjectPath,
        read_offset: Option<i64>,
        read_limit: Option<i64>,
        metadata_only: bool,
    ) -> Result<Option<(Option<Object>, Vec<u8>)>, Error> {
        let retrier = self.retrier.clone();
        let client = self.client.clone();
        let object_clone = object.clone();
        let self_clone = self.clone();

        let operation_stream = futures::stream::unfold(
            (client, object_clone, self_clone),
            move |(client, object, self_ref)| {
                let read_offset = read_offset;
                let read_limit = read_limit;
                let metadata_only = metadata_only;

                async move {
                    let attempt_result = async {
                        let mut client_guard = client.write().await;
                        let request = ReadObjectRequest {
                            bucket: object.get_formatted_bucket(),
                            object: object.path.clone(),
                            read_offset: read_offset.unwrap_or(0),
                            read_limit: read_limit.unwrap_or(0),
                            ..Default::default()
                        };

                        let auth_request = self_ref.prepare_request(request, object.clone()).await;
                        let response = client_guard
                            .handle_request(|client| {
                                let future = client.read_object(auth_request);
                                Box::pin(future)
                            })
                            .await;

                        match response {
                            Ok(response) => {
                                let mut content = Vec::new();
                                let mut metadata = None;
                                let mut stream = response.into_inner();

                                if let Some(Ok(first_message)) = stream.next().await {
                                    metadata = first_message.metadata;
                                    if metadata_only {
                                        return Ok(Some((metadata, content)));
                                    }
                                }

                                while let Some(chunk) = stream.next().await {
                                    match chunk {
                                        Ok(data) => {
                                            if let Some(checksummed_data) = data.checksummed_data {
                                                content.extend(checksummed_data.content);
                                            }
                                        }
                                        Err(e) => {
                                            return Err(make_err!(
                                                Code::Unavailable,
                                                "Error reading object data: {e:?}"
                                            ));
                                        }
                                    }
                                }

                                Ok(Some((metadata, content)))
                            }
                            Err(e) => match e.code {
                                Code::NotFound => Ok(None),
                                _ => Err(make_err!(
                                    Code::Unavailable,
                                    "Failed to read object: {e:?}"
                                )),
                            },
                        }
                    }
                    .await;

                    Some((RetryResult::Ok(attempt_result), (client, object, self_ref)))
                }
            },
        );

        retrier.retry(operation_stream).await?
    }

    pub async fn read_object_metadata(&self, object: ObjectPath) -> Result<Option<Object>, Error> {
        Ok(self
            .read_object(object, None, None, true)
            .await?
            .and_then(|(metadata, _)| metadata))
    }

    pub async fn read_object_content(
        &self,
        object: ObjectPath,
        start: i64,
        end: Option<i64>,
    ) -> Result<Vec<u8>, Error> {
        match self
            .read_object(object.clone(), Some(start), end.map(|e| e - start), false)
            .await?
        {
            Some((_, content)) => Ok(content),
            None => Err(make_err!(
                Code::NotFound,
                "Object not found: {}",
                object.path
            )),
        }
    }
}
