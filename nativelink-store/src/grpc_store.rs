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

use std::borrow::Cow;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use futures::stream::{unfold, FuturesUnordered};
use futures::{future, Future, Stream, StreamExt, TryFutureExt, TryStreamExt};
use nativelink_config::stores::GrpcSpec;
use nativelink_error::{error_if, make_input_err, Error, ResultExt};
use nativelink_metric::MetricsComponent;
use nativelink_proto::build::bazel::remote::execution::v2::action_cache_client::ActionCacheClient;
use nativelink_proto::build::bazel::remote::execution::v2::content_addressable_storage_client::ContentAddressableStorageClient;
use nativelink_proto::build::bazel::remote::execution::v2::{
    ActionResult, BatchReadBlobsRequest, BatchReadBlobsResponse, BatchUpdateBlobsRequest,
    BatchUpdateBlobsResponse, FindMissingBlobsRequest, FindMissingBlobsResponse,
    GetActionResultRequest, GetTreeRequest, GetTreeResponse, UpdateActionResultRequest,
};
use nativelink_proto::google::bytestream::byte_stream_client::ByteStreamClient;
use nativelink_proto::google::bytestream::{
    QueryWriteStatusRequest, QueryWriteStatusResponse, ReadRequest, ReadResponse, WriteRequest,
    WriteResponse,
};
use nativelink_util::buf_channel::{DropCloserReadHalf, DropCloserWriteHalf};
use nativelink_util::common::DigestInfo;
use nativelink_util::connection_manager::ConnectionManager;
use nativelink_util::digest_hasher::{default_digest_hasher_func, ACTIVE_HASHER_FUNC};
use nativelink_util::health_utils::HealthStatusIndicator;
use nativelink_util::origin_context::ActiveOriginContext;
use nativelink_util::proto_stream_utils::{
    FirstStream, WriteRequestStreamWrapper, WriteState, WriteStateWrapper,
};
use nativelink_util::resource_info::{is_supported_digest_function, ResourceInfo};
use nativelink_util::retry::{Retrier, RetryResult};
use nativelink_util::store_trait::{StoreDriver, StoreKey, UploadSizeInfo};
use nativelink_util::{default_health_status_indicator, tls_utils};
use parking_lot::Mutex;
use prost::Message;
use rand::rngs::OsRng;
use rand::Rng;
use tokio::time::sleep;
use tonic::{IntoRequest, Request, Response, Status, Streaming};
use tracing::{event, Level};
use uuid::Uuid;

// This store is usually a pass-through store, but can also be used as a CAS store. Using it as an
// AC store has one major side-effect... The has() function may not give the proper size of the
// underlying data. This might cause issues if embedded in certain stores.
#[derive(MetricsComponent)]
pub struct GrpcStore {
    #[metric(help = "Instance name for the store")]
    instance_name: String,
    store_type: nativelink_config::stores::StoreType,
    retrier: Retrier,
    connection_manager: ConnectionManager,
}

impl GrpcStore {
    pub async fn new(spec: &GrpcSpec) -> Result<Arc<Self>, Error> {
        let jitter_amt = spec.retry.jitter;
        Self::new_with_jitter(
            spec,
            Box::new(move |delay: Duration| {
                if jitter_amt == 0. {
                    return delay;
                }
                let min = 1. - (jitter_amt / 2.);
                let max = 1. + (jitter_amt / 2.);
                delay.mul_f32(OsRng.gen_range(min..max))
            }),
        )
        .await
    }

    pub async fn new_with_jitter(
        spec: &GrpcSpec,
        jitter_fn: Box<dyn Fn(Duration) -> Duration + Send + Sync>,
    ) -> Result<Arc<Self>, Error> {
        error_if!(
            spec.endpoints.is_empty(),
            "Expected at least 1 endpoint in GrpcStore"
        );
        let mut endpoints = Vec::with_capacity(spec.endpoints.len());
        for endpoint_config in &spec.endpoints {
            let endpoint = tls_utils::endpoint(endpoint_config)
                .map_err(|e| make_input_err!("Invalid URI for GrpcStore endpoint : {e:?}"))?;
            endpoints.push(endpoint);
        }

        let jitter_fn = Arc::new(jitter_fn);
        Ok(Arc::new(GrpcStore {
            instance_name: spec.instance_name.clone(),
            store_type: spec.store_type,
            retrier: Retrier::new(
                Arc::new(|duration| Box::pin(sleep(duration))),
                jitter_fn.clone(),
                spec.retry.clone(),
            ),
            connection_manager: ConnectionManager::new(
                endpoints.into_iter(),
                spec.connections_per_endpoint,
                spec.max_concurrent_requests,
                spec.retry.clone(),
                jitter_fn,
            ),
        }))
    }

    async fn perform_request<F, Fut, R, I>(&self, input: I, mut request: F) -> Result<R, Error>
    where
        F: FnMut(I) -> Fut + Send + Copy,
        Fut: Future<Output = Result<R, Error>> + Send,
        R: Send,
        I: Send + Clone,
    {
        self.retrier
            .retry(unfold(input, move |input| async move {
                let input_clone = input.clone();
                Some((
                    request(input_clone)
                        .await
                        .map_or_else(RetryResult::Retry, RetryResult::Ok),
                    input,
                ))
            }))
            .await
    }

    pub async fn find_missing_blobs(
        &self,
        grpc_request: Request<FindMissingBlobsRequest>,
    ) -> Result<Response<FindMissingBlobsResponse>, Error> {
        error_if!(
            matches!(self.store_type, nativelink_config::stores::StoreType::ac),
            "CAS operation on AC store"
        );

        let mut request = grpc_request.into_inner();
        request.instance_name.clone_from(&self.instance_name);
        self.perform_request(request, |request| async move {
            let channel = self
                .connection_manager
                .connection()
                .await
                .err_tip(|| "in find_missing_blobs")?;
            ContentAddressableStorageClient::new(channel)
                .find_missing_blobs(Request::new(request))
                .await
                .err_tip(|| "in GrpcStore::find_missing_blobs")
        })
        .await
    }

    pub async fn batch_update_blobs(
        &self,
        grpc_request: Request<BatchUpdateBlobsRequest>,
    ) -> Result<Response<BatchUpdateBlobsResponse>, Error> {
        error_if!(
            matches!(self.store_type, nativelink_config::stores::StoreType::ac),
            "CAS operation on AC store"
        );

        let mut request = grpc_request.into_inner();
        request.instance_name.clone_from(&self.instance_name);
        self.perform_request(request, |request| async move {
            let channel = self
                .connection_manager
                .connection()
                .await
                .err_tip(|| "in batch_update_blobs")?;
            ContentAddressableStorageClient::new(channel)
                .batch_update_blobs(Request::new(request))
                .await
                .err_tip(|| "in GrpcStore::batch_update_blobs")
        })
        .await
    }

    pub async fn batch_read_blobs(
        &self,
        grpc_request: Request<BatchReadBlobsRequest>,
    ) -> Result<Response<BatchReadBlobsResponse>, Error> {
        error_if!(
            matches!(self.store_type, nativelink_config::stores::StoreType::ac),
            "CAS operation on AC store"
        );

        let mut request = grpc_request.into_inner();
        request.instance_name.clone_from(&self.instance_name);
        self.perform_request(request, |request| async move {
            let channel = self
                .connection_manager
                .connection()
                .await
                .err_tip(|| "in batch_read_blobs")?;
            ContentAddressableStorageClient::new(channel)
                .batch_read_blobs(Request::new(request))
                .await
                .err_tip(|| "in GrpcStore::batch_read_blobs")
        })
        .await
    }

    pub async fn get_tree(
        &self,
        grpc_request: Request<GetTreeRequest>,
    ) -> Result<Response<Streaming<GetTreeResponse>>, Error> {
        error_if!(
            matches!(self.store_type, nativelink_config::stores::StoreType::ac),
            "CAS operation on AC store"
        );

        let mut request = grpc_request.into_inner();
        request.instance_name.clone_from(&self.instance_name);
        self.perform_request(request, |request| async move {
            let channel = self
                .connection_manager
                .connection()
                .await
                .err_tip(|| "in get_tree")?;
            ContentAddressableStorageClient::new(channel)
                .get_tree(Request::new(request))
                .await
                .err_tip(|| "in GrpcStore::get_tree")
        })
        .await
    }

    fn get_read_request(&self, mut request: ReadRequest) -> Result<ReadRequest, Error> {
        const IS_UPLOAD_FALSE: bool = false;
        let mut resource_info = ResourceInfo::new(&request.resource_name, IS_UPLOAD_FALSE)?;
        if resource_info.instance_name != self.instance_name {
            resource_info.instance_name = Cow::Borrowed(&self.instance_name);
            request.resource_name = resource_info.to_string(IS_UPLOAD_FALSE);
        }
        Ok(request)
    }

    async fn read_internal(
        &self,
        request: ReadRequest,
    ) -> Result<impl Stream<Item = Result<ReadResponse, Status>>, Error> {
        let channel = self
            .connection_manager
            .connection()
            .await
            .err_tip(|| "in read_internal")?;
        let mut response = ByteStreamClient::new(channel)
            .read(Request::new(request))
            .await
            .err_tip(|| "in GrpcStore::read")?
            .into_inner();
        let first_response = response
            .message()
            .await
            .err_tip(|| "Fetching first chunk in GrpcStore::read()")?;
        Ok(FirstStream::new(first_response, response))
    }

    pub async fn read(
        &self,
        grpc_request: impl IntoRequest<ReadRequest>,
    ) -> Result<impl Stream<Item = Result<ReadResponse, Status>>, Error> {
        const IS_UPLOAD_FALSE: bool = false;

        let request = self.get_read_request(grpc_request.into_request().into_inner())?;
        let resource_name = &request.resource_name;
        let resource_info = ResourceInfo::new(resource_name, IS_UPLOAD_FALSE)
            .err_tip(|| "Failed to parse resource_name in GrpcStore::read")?;

        let digest_function = resource_info.digest_function.as_deref().unwrap_or("sha256");

        if !is_supported_digest_function(digest_function) {
            return Err(make_input_err!(
                "Unsupported digest_function: {} in resource_name '{}'",
                digest_function,
                resource_name
            ));
        }

        error_if!(
            matches!(self.store_type, nativelink_config::stores::StoreType::ac),
            "CAS operation on AC store"
        );

        self.perform_request(request, |request| async move {
            self.read_internal(request).await
        })
        .await
    }

    pub async fn write<T, E>(
        &self,
        stream: WriteRequestStreamWrapper<T>,
    ) -> Result<Response<WriteResponse>, Error>
    where
        T: Stream<Item = Result<WriteRequest, E>> + Unpin + Send + 'static,
        E: Into<Error> + 'static,
    {
        error_if!(
            matches!(self.store_type, nativelink_config::stores::StoreType::ac),
            "CAS operation on AC store"
        );

        let local_state = Arc::new(Mutex::new(WriteState::new(
            self.instance_name.clone(),
            stream,
        )));

        let result = self
            .retrier
            .retry(unfold(local_state, move |local_state| async move {
                // The client write may occur on a separate thread and
                // therefore in order to share the state with it we have to
                // wrap it in a Mutex and retrieve it after the write
                // has completed.  There is no way to get the value back
                // from the client.
                let result = self
                    .connection_manager
                    .connection()
                    .and_then(|channel| async {
                        ByteStreamClient::new(channel)
                            .write(WriteStateWrapper::new(local_state.clone()))
                            .await
                            .err_tip(|| "in GrpcStore::write")
                    })
                    .await;

                // Get the state back from StateWrapper, this should be
                // uncontended since write has returned.
                let mut local_state_locked = local_state.lock();

                let result = if let Some(err) = local_state_locked.take_read_stream_error() {
                    // If there was an error with the stream, then don't retry.
                    RetryResult::Err(err.append("Where read_stream_error was set"))
                } else {
                    // On error determine whether it is possible to retry.
                    match result {
                        Err(err) => {
                            if local_state_locked.can_resume() {
                                local_state_locked.resume();
                                RetryResult::Retry(err)
                            } else {
                                RetryResult::Err(err.append("Retry is not possible"))
                            }
                        }
                        Ok(response) => RetryResult::Ok(response),
                    }
                };

                drop(local_state_locked);
                Some((result, local_state))
            }))
            .await?;
        Ok(result)
    }

    pub async fn query_write_status(
        &self,
        grpc_request: Request<QueryWriteStatusRequest>,
    ) -> Result<Response<QueryWriteStatusResponse>, Error> {
        const IS_UPLOAD_TRUE: bool = true;

        error_if!(
            matches!(self.store_type, nativelink_config::stores::StoreType::ac),
            "CAS operation on AC store"
        );

        let mut request = grpc_request.into_inner();

        let mut request_info = ResourceInfo::new(&request.resource_name, IS_UPLOAD_TRUE)?;
        if request_info.instance_name != self.instance_name {
            request_info.instance_name = Cow::Borrowed(&self.instance_name);
            request.resource_name = request_info.to_string(IS_UPLOAD_TRUE);
        }

        self.perform_request(request, |request| async move {
            let channel = self
                .connection_manager
                .connection()
                .await
                .err_tip(|| "in query_write_status")?;
            ByteStreamClient::new(channel)
                .query_write_status(Request::new(request))
                .await
                .err_tip(|| "in GrpcStore::query_write_status")
        })
        .await
    }

    pub async fn get_action_result(
        &self,
        grpc_request: Request<GetActionResultRequest>,
    ) -> Result<Response<ActionResult>, Error> {
        let mut request = grpc_request.into_inner();
        request.instance_name.clone_from(&self.instance_name);
        self.perform_request(request, |request| async move {
            let channel = self
                .connection_manager
                .connection()
                .await
                .err_tip(|| "in get_action_result")?;
            ActionCacheClient::new(channel)
                .get_action_result(Request::new(request))
                .await
                .err_tip(|| "in GrpcStore::get_action_result")
        })
        .await
    }

    pub async fn update_action_result(
        &self,
        grpc_request: Request<UpdateActionResultRequest>,
    ) -> Result<Response<ActionResult>, Error> {
        let mut request = grpc_request.into_inner();
        request.instance_name.clone_from(&self.instance_name);
        self.perform_request(request, |request| async move {
            let channel = self
                .connection_manager
                .connection()
                .await
                .err_tip(|| "in update_action_result")?;
            ActionCacheClient::new(channel)
                .update_action_result(Request::new(request))
                .await
                .err_tip(|| "in GrpcStore::update_action_result")
        })
        .await
    }

    async fn get_action_result_from_digest(
        &self,
        digest: DigestInfo,
    ) -> Result<Response<ActionResult>, Error> {
        let action_result_request = GetActionResultRequest {
            instance_name: self.instance_name.clone(),
            action_digest: Some(digest.into()),
            inline_stdout: false,
            inline_stderr: false,
            inline_output_files: Vec::new(),
            digest_function: ActiveOriginContext::get_value(&ACTIVE_HASHER_FUNC)
                .err_tip(|| "In get_action_from_store")?
                .map_or_else(default_digest_hasher_func, |v| *v)
                .proto_digest_func()
                .into(),
        };
        self.get_action_result(Request::new(action_result_request))
            .await
    }

    async fn get_action_result_as_part(
        &self,
        digest: DigestInfo,
        writer: &mut DropCloserWriteHalf,
        offset: usize,
        length: Option<usize>,
    ) -> Result<(), Error> {
        let action_result = self
            .get_action_result_from_digest(digest)
            .await
            .map(Response::into_inner)
            .err_tip(|| "Action result not found")?;
        // TODO: Would be better to avoid all the encoding and decoding in this
        //       file, however there's no way to currently get raw bytes from a
        //       generated prost request unfortunately.
        let mut value = BytesMut::new();
        action_result
            .encode(&mut value)
            .err_tip(|| "Could not encode upstream action result")?;

        let default_len = value.len() - offset;
        let length = length.unwrap_or(default_len).min(default_len);
        if length > 0 {
            writer
                .send(value.freeze().slice(offset..offset + length))
                .await
                .err_tip(|| "Failed to write data in grpc store")?;
        }
        writer
            .send_eof()
            .err_tip(|| "Failed to write EOF in grpc store get_action_result_as_part")?;
        Ok(())
    }

    async fn update_action_result_from_bytes(
        &self,
        digest: DigestInfo,
        mut reader: DropCloserReadHalf,
    ) -> Result<(), Error> {
        let action_result = ActionResult::decode(reader.consume(None).await?)
            .err_tip(|| "Failed to decode ActionResult in update_action_result_from_bytes")?;
        let update_action_request = UpdateActionResultRequest {
            instance_name: self.instance_name.clone(),
            action_digest: Some(digest.into()),
            action_result: Some(action_result),
            results_cache_policy: None,
            digest_function: ActiveOriginContext::get_value(&ACTIVE_HASHER_FUNC)
                .err_tip(|| "In get_action_from_store")?
                .map_or_else(default_digest_hasher_func, |v| *v)
                .proto_digest_func()
                .into(),
        };
        self.update_action_result(Request::new(update_action_request))
            .await
            .map(|_| ())
    }
}

#[async_trait]
impl StoreDriver for GrpcStore {
    // NOTE: This function can only be safely used on CAS stores. AC stores may return a size that
    // is incorrect.
    async fn has_with_results(
        self: Pin<&Self>,
        keys: &[StoreKey<'_>],
        results: &mut [Option<u64>],
    ) -> Result<(), Error> {
        let digest_function = ActiveOriginContext::get_value(&ACTIVE_HASHER_FUNC)
            .err_tip(|| "In GrpcStore::has_with_results")?
            .map_or_else(default_digest_hasher_func, |v| *v)
            .to_string();

        if !is_supported_digest_function(&digest_function) {
            return Err(make_input_err!(
                "Unsupported digest_function: {}",
                digest_function
            ));
        }

        if matches!(self.store_type, nativelink_config::stores::StoreType::ac) {
            keys.iter()
                .zip(results.iter_mut())
                .map(|(key, result)| async move {
                    // The length of an AC is incorrect, so we don't figure out the
                    // length, instead the biggest possible result is returned in the
                    // hope that we detect incorrect usage.
                    self.get_action_result_from_digest(key.borrow().into_digest())
                        .await?;
                    *result = Some(u64::MAX);
                    Ok::<_, Error>(())
                })
                .collect::<FuturesUnordered<_>>()
                .try_for_each(|()| future::ready(Ok(())))
                .await
                .err_tip(|| "Getting upstream action cache entry")?;
            return Ok(());
        }

        let missing_blobs_response = self
            .find_missing_blobs(Request::new(FindMissingBlobsRequest {
                instance_name: self.instance_name.clone(),
                blob_digests: keys
                    .iter()
                    .map(|k| k.borrow().into_digest().into())
                    .collect(),
                digest_function: ActiveOriginContext::get_value(&ACTIVE_HASHER_FUNC)
                    .err_tip(|| "In GrpcStore::has_with_results")?
                    .map_or_else(default_digest_hasher_func, |v| *v)
                    .proto_digest_func()
                    .into(),
            }))
            .await?
            .into_inner();

        // Since the ordering is not guaranteed above, the matching has to check
        // all missing blobs against all entries in the unsorted digest list.
        // To optimise this, the missing digests are sorted and then it is
        // efficient to perform a binary search for each digest within the
        // missing list.
        let mut missing_digests =
            Vec::with_capacity(missing_blobs_response.missing_blob_digests.len());
        for missing_digest in missing_blobs_response.missing_blob_digests {
            missing_digests.push(DigestInfo::try_from(missing_digest)?);
        }
        missing_digests.sort_unstable();
        for (digest, result) in keys
            .iter()
            .map(|v| v.borrow().into_digest())
            .zip(results.iter_mut())
        {
            match missing_digests.binary_search(&digest) {
                Ok(_) => *result = None,
                Err(_) => *result = Some(digest.size_bytes()),
            }
        }

        Ok(())
    }

    async fn update(
        self: Pin<&Self>,
        key: StoreKey<'_>,
        reader: DropCloserReadHalf,
        _size_info: UploadSizeInfo,
    ) -> Result<(), Error> {
        let digest = key.into_digest();
        if matches!(self.store_type, nativelink_config::stores::StoreType::ac) {
            return self.update_action_result_from_bytes(digest, reader).await;
        }

        let mut buf = Uuid::encode_buffer();
        let resource_name = format!(
            "{}/uploads/{}/blobs/{}/{}",
            &self.instance_name,
            Uuid::new_v4().hyphenated().encode_lower(&mut buf),
            digest.packed_hash(),
            digest.size_bytes(),
        );

        struct LocalState {
            resource_name: String,
            reader: DropCloserReadHalf,
            did_error: bool,
            bytes_received: i64,
        }
        let local_state = LocalState {
            resource_name,
            reader,
            did_error: false,
            bytes_received: 0,
        };

        let stream = Box::pin(unfold(local_state, |mut local_state| async move {
            if local_state.did_error {
                event!(
                    Level::ERROR,
                    "GrpcStore::update() polled stream after error was returned"
                );
                return None;
            }
            let data = match local_state
                .reader
                .recv()
                .await
                .err_tip(|| "In GrpcStore::update()")
            {
                Ok(data) => data,
                Err(err) => {
                    local_state.did_error = true;
                    return Some((Err(err), local_state));
                }
            };

            let write_offset = local_state.bytes_received;
            local_state.bytes_received += data.len() as i64;

            Some((
                Ok(WriteRequest {
                    resource_name: local_state.resource_name.clone(),
                    write_offset,
                    finish_write: data.is_empty(), // EOF is when no data was polled.
                    data,
                }),
                local_state,
            ))
        }));

        self.write(
            WriteRequestStreamWrapper::from(stream)
                .await
                .err_tip(|| "in GrpcStore::update()")?,
        )
        .await
        .err_tip(|| "in GrpcStore::update()")?;

        Ok(())
    }

    async fn get_part(
        self: Pin<&Self>,
        key: StoreKey<'_>,
        writer: &mut DropCloserWriteHalf,
        offset: u64,
        length: Option<u64>,
    ) -> Result<(), Error> {
        let digest = key.into_digest();
        if matches!(self.store_type, nativelink_config::stores::StoreType::ac) {
            let offset = usize::try_from(offset).err_tip(|| "Could not convert offset to usize")?;
            let length = length
                .map(|v| usize::try_from(v).err_tip(|| "Could not convert length to usize"))
                .transpose()?;

            return self
                .get_action_result_as_part(digest, writer, offset, length)
                .await;
        }

        // Shortcut for empty blobs.
        if digest.size_bytes() == 0 {
            return writer.send_eof();
        }

        let resource_name = format!(
            "{}/blobs/{}/{}",
            &self.instance_name,
            digest.packed_hash(),
            digest.size_bytes(),
        );

        struct LocalState<'a> {
            resource_name: String,
            writer: &'a mut DropCloserWriteHalf,
            read_offset: i64,
            read_limit: i64,
        }

        let local_state = LocalState {
            resource_name,
            writer,
            read_offset: i64::try_from(offset).err_tip(|| "Could not convert offset to i64")?,
            read_limit: i64::try_from(length.unwrap_or(0))
                .err_tip(|| "Could not convert length to i64")?,
        };

        self.retrier
            .retry(unfold(local_state, move |mut local_state| async move {
                let request = ReadRequest {
                    resource_name: local_state.resource_name.clone(),
                    read_offset: local_state.read_offset,
                    read_limit: local_state.read_limit,
                };
                let mut stream = match self
                    .read_internal(request)
                    .await
                    .err_tip(|| "in GrpcStore::get_part()")
                {
                    Ok(stream) => stream,
                    Err(err) => return Some((RetryResult::Retry(err), local_state)),
                };

                loop {
                    let data = match stream.next().await {
                        // Create an empty response to represent EOF.
                        None => bytes::Bytes::new(),
                        Some(Ok(message)) => message.data,
                        Some(Err(status)) => {
                            return Some((
                                RetryResult::Retry(
                                    Into::<Error>::into(status)
                                        .append("While fetching message in GrpcStore::get_part()"),
                                ),
                                local_state,
                            ))
                        }
                    };
                    let length = data.len() as i64;
                    // This is the usual exit from the loop at EOF.
                    if length == 0 {
                        let eof_result = local_state
                            .writer
                            .send_eof()
                            .err_tip(|| "Could not send eof in GrpcStore::get_part()")
                            .map_or_else(RetryResult::Err, RetryResult::Ok);
                        return Some((eof_result, local_state));
                    }
                    // Forward the data upstream.
                    if let Err(err) = local_state
                        .writer
                        .send(data)
                        .await
                        .err_tip(|| "While sending in GrpcStore::get_part()")
                    {
                        return Some((RetryResult::Err(err), local_state));
                    }
                    local_state.read_offset += length;
                }
            }))
            .await
    }

    fn inner_store(&self, _digest: Option<StoreKey>) -> &dyn StoreDriver {
        self
    }

    fn as_any<'a>(&'a self) -> &'a (dyn std::any::Any + Sync + Send + 'static) {
        self
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Sync + Send + 'static> {
        self
    }
}

default_health_status_indicator!(GrpcStore);
