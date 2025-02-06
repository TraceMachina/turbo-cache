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
use futures::stream::{unfold, StreamExt};
use nativelink_config::stores::GcsSpec;
use nativelink_error::{make_err, Code, Error, ResultExt};
use nativelink_metric::MetricsComponent;
use nativelink_proto::build::bazel::remote::execution::v2 as remexec;
use nativelink_proto::google::storage::v2::storage_client::StorageClient;
use nativelink_proto::google::storage::v2::{Object, WriteObjectSpec};
use nativelink_util::buf_channel::{DropCloserReadHalf, DropCloserWriteHalf};
use nativelink_util::health_utils::{HealthStatus, HealthStatusIndicator};
use nativelink_util::instant_wrapper::InstantWrapper;
use nativelink_util::retry::{Retrier, RetryResult};
use nativelink_util::store_trait::{StoreDriver, StoreKey, UploadSizeInfo};
use rand::rngs::OsRng;
use rand::Rng;
use tokio::time::sleep;
use tonic::transport::Channel;

use crate::cas_utils::is_zero_digest;

const DEFAULT_MAX_RETRY_BUFFER_PER_REQUEST: usize = 5 * 1024 * 1024; // 5MB
const DEFAULT_MULTIPART_MAX_CONCURRENT_UPLOADS: usize = 10;

/// GcsStore provides a Store implementation backed by Google Cloud Storage.
/// It uses the official GCS gRPC API for all operations.
#[derive(Clone, MetricsComponent)]
pub struct GcsStore<NowFn>
{
    /// The GCS client for making API calls
    client: StorageClient<Channel>,
    /// Function to get current time
    now_fn: NowFn,
    /// The GCS bucket name
    #[metric(help = "The GCS bucket name")]
    bucket: String,
    /// Optional prefix for all object keys
    #[metric(help = "The key prefix for the GCS store")]
    key_prefix: String,
    /// Retry configuration for failed operations
    retrier: Retrier,
    /// Time after which objects are considered expired
    #[metric(help = "The number of seconds to consider an object expired")]
    consider_expired_after_s: i64,
    /// Maximum buffer size for retrying requests
    #[metric(help = "The number of bytes to buffer for retrying requests")]
    max_retry_buffer_per_request: usize,
    /// Maximum concurrent uploads for multipart operations
    #[metric(help = "The number of concurrent uploads allowed for multipart uploads")]
    multipart_max_concurrent_uploads: usize,
}

impl<I, NowFn> GcsStore<NowFn>
where
    I: InstantWrapper,
    NowFn: Fn() -> I + Send + Sync + Unpin + 'static,
{
    /// Creates a new GcsStore instance.
    ///
    /// Implementation steps:
    /// 1. Set up GCS client with proper authentication
    /// 2. Initialize connection to GCS using provided configuration
    /// 3. Set up retry policy and other configurations
    /// 4. Return wrapped in Arc for thread-safety
    pub async fn new(spec: &GcsSpec, now_fn: NowFn) -> Result<Arc<Self>, Error> {
        let jitter_amt = spec.retry.jitter;
        let jitter_fn = Arc::new(move |delay: Duration| {
            if jitter_amt == 0. {
                return delay;
            }
            let min = 1. - (jitter_amt / 2.);
            let max = 1. + (jitter_amt / 2.);
            delay.mul_f32(OsRng.gen_range(min..max))
        });

        // Create GCS client with default credentials
        let channel = Channel::from_static("https://storage.googleapis.com")
            .connect()
            .await
            .err_tip(|| "Failed to create GCS channel")?;
        
        let client = StorageClient::new(channel);

        // Create GcsStore instance with configuration
        let store = Self {
            client,
            now_fn,
            bucket: spec.bucket.clone(),
            key_prefix: spec.key_prefix.clone().unwrap_or_default(),
            retrier: Retrier::new(
                Arc::new(|duration| Box::pin(sleep(duration))),
                jitter_fn,
                spec.retry.clone(),
            ),
            consider_expired_after_s: i64::from(spec.consider_expired_after_s),
            max_retry_buffer_per_request: spec.max_retry_buffer_per_request
                .unwrap_or(DEFAULT_MAX_RETRY_BUFFER_PER_REQUEST),
            multipart_max_concurrent_uploads: spec.multipart_max_concurrent_uploads
                .unwrap_or(DEFAULT_MULTIPART_MAX_CONCURRENT_UPLOADS),
        };

        Ok(Arc::new(store))
    }

    /// Helper method to construct the full GCS object path
    /// by combining the key_prefix with the object key.
    fn make_gcs_path(&self, key: &StoreKey<'_>) -> String {
        match self.key_prefix.is_empty() {
            true => key.as_str().to_string(),
            false => format!("{}/{}", self.key_prefix, key.as_str()),
        }
    }
}

#[async_trait]
impl<I, NowFn> StoreDriver for GcsStore<NowFn>
where
    I: InstantWrapper,
    NowFn: Fn() -> I + Send + Sync + Unpin + 'static,
{
    /// Checks if multiple objects exist in GCS and returns their sizes.
    ///
    /// Implementation steps:
    /// 1. Handle zero digest case
    /// 2. Batch object metadata requests for efficiency
    /// 3. Use Object.Get API to check existence and get size
    /// 4. Handle expired objects based on consider_expired_after_s
    /// 5. Return sizes for existing objects, None for missing ones
    async fn has_with_results(
        self: Pin<&Self>,
        keys: &[StoreKey<'_>],
        results: &mut [Option<u64>],
    ) -> Result<(), Error> {
        use futures::stream::{FuturesUnordered, StreamExt};
        use nativelink_proto::google::storage::v2::Object;

        for (key, result) in keys.iter().zip(results.iter_mut()) {
            // Handle zero digest case
            if is_zero_digest(key.borrow()) {
                *result = Some(0);
                continue;
            }

            let gcs_path = self.make_gcs_path(key);
            
            // Use the retrier to handle transient failures
            match self.retrier.retry(async {
                let response = self.client
                    .get_object()
                    .bucket(&self.bucket)
                    .object(&gcs_path)
                    .send()
                    .await;

                match response {
                    Ok(obj) => {
                        let size = obj.into_inner().size.unwrap_or(0);
                        RetryResult::Ok(Some(size))
                    }
                    Err(status) if status.code() == tonic::Code::NotFound => {
                        RetryResult::Ok(None)
                    }
                    Err(e) => RetryResult::Retry(make_err!(
                        Code::Aborted,
                        "Failed to get object metadata: {}", e
                    ))
                }
            }).await? {
                Some(size) => *result = Some(u64::try_from(size).err_tip(|| "Invalid object size")?),
                None => *result = None,
            }
        }
        Ok(())
    }

    /// Uploads an object to GCS.
    ///
    /// Implementation steps:
    /// 1. Handle zero digest case
    /// 2. For small files (<5MB):
    ///    - Use simple upload with Object.Write API
    /// 3. For large files:
    ///    - Use resumable upload protocol
    ///    - Initialize with Object.StartResumableWrite
    ///    - Upload chunks with Object.Write
    ///    - Handle retries and failures
    /// 4. Verify upload completion
    async fn update(
        self: Pin<&Self>,
        digest: StoreKey<'_>,
        mut reader: DropCloserReadHalf,
        upload_size: UploadSizeInfo,
    ) -> Result<(), Error> {
        // Handle zero digest case
        if is_zero_digest(digest.borrow()) {
            return Ok(());
        }

        let gcs_path = self.make_gcs_path(&digest);
        
        // Set maximum buffer size for retrying uploads
        reader.set_max_recent_data_size(
            u64::try_from(self.max_retry_buffer_per_request)
                .err_tip(|| "Could not convert max_retry_buffer_per_request to u64")?,
        );

       // Get the size if known
        let size = match upload_size {
            UploadSizeInfo::ExactSize(size) | UploadSizeInfo::MaxSize(size) => Some(size),
            _ => None,
        };

        // For small files or unknown size, use simple upload
        if size.map_or(true, |s| s < 5 * 1024 * 1024) {
            // Simple upload
            return self.retrier.retry(unfold(reader, move |mut reader| async move {
                let mut buffer = Vec::new();
                while let Some(chunk) = reader.next().await {
                    let chunk = chunk.err_tip(|| "Failed to read chunk from reader").unwrap();
                    buffer.extend_from_slice(&chunk);
                }

                let retry_result = match self.client
                    .write_object()
                    .bucket(&self.bucket)
                    .object(&gcs_path)
                    .write_object_spec(nativelink_proto::google::storage::v2::WriteObjectSpec {
                        resource: Some(nativelink_proto::google::storage::v2::Object {
                            name: gcs_path.clone(),
                            bucket: self.bucket.clone(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    })
                    .data(buffer)
                    .send()
                    .await
                {
                    Ok(_) => RetryResult::Ok(()),
                    Err(e) => RetryResult::Retry(make_err!(
                        Code::Aborted,
                        "Failed to upload object: {}", e
                    ))
                };
                Some((retry_result, reader))
            })).await;
        }

        // For large files, use resumable upload
        let upload = self.retrier.retry(unfold((), move |_| async move {
            let retry_result = match self.client
                .start_resumable_write()
                .write_object_spec(nativelink_proto::google::storage::v2::WriteObjectSpec {
                    resource: Some(nativelink_proto::google::storage::v2::Object {
                        name: gcs_path.clone(),
                        bucket: self.bucket.clone(),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .send()
                .await
            {
                Ok(response) => RetryResult::Ok(response.into_inner().upload_id),
                Err(e) => RetryResult::Retry(make_err!(
                    Code::Aborted,
                    "Failed to start resumable upload: {}", e
                ))
            };
            Some((retry_result, ()))
        })).await?;

        let mut offset = 0u64;
        let mut buffer = Vec::new();

        // Upload chunks
        while let Some(chunk) = reader.next().await {
            let chunk = chunk.err_tip(|| "Failed to read chunk from reader")?;
            buffer.extend_from_slice(&chunk);

            // Upload when buffer reaches optimal size or on last chunk
            if buffer.len() >= 5 * 1024 * 1024 {
                let buffer_clone = buffer.clone();
                self.retrier.retry(unfold((), move |_| async move {
                    let retry_result = match self.client
                        .write_object()
                        .bucket(&self.bucket)
                        .object(&gcs_path)
                        .upload_id(&upload)
                        .write_offset(offset)
                        .data(buffer_clone.clone())
                        .send()
                        .await
                    {
                        Ok(_) => RetryResult::Ok(()),
                        Err(e) => RetryResult::Retry(make_err!(
                            Code::Aborted,
                            "Failed to upload chunk: {}", e
                        ))
                    };
                    Some((retry_result, ()))
                })).await?;

                offset += u64::try_from(buffer.len())
                    .err_tip(|| "Could not convert buffer length to u64")?;
                buffer.clear();
            }
        }

        // Upload any remaining data
        if !buffer.is_empty() {
            let buffer_clone = buffer.clone();
            self.retrier.retry(unfold((), move |_| async move {
                let retry_result = match self.client
                    .write_object()
                    .bucket(&self.bucket)
                    .object(&gcs_path)
                    .upload_id(&upload)
                    .write_offset(offset)
                    .data(buffer_clone.clone())
                    .finish_write(true)
                    .send()
                    .await
                {
                    Ok(_) => RetryResult::Ok(()),
                    Err(e) => RetryResult::Retry(make_err!(
                        Code::Aborted,
                        "Failed to upload final chunk: {}", e
                    ))
                };
                Some((retry_result, ()))
            })).await?;
        }

        Ok(())
    }

    /// Downloads a part of an object from GCS.
    ///
    /// Implementation steps:
    /// 1. Handle zero digest case
    /// 2. Calculate byte range based on offset and length
    /// 3. Use Object.Read API with range header
    /// 4. Stream data to writer
    /// 5. Handle errors and retries
    async fn get_part(
        self: Pin<&Self>,
        key: StoreKey<'_>,
        writer: &mut DropCloserWriteHalf,
        offset: u64,
        length: Option<u64>,
    ) -> Result<(), Error> {
        // Handle zero digest case
        if is_zero_digest(key.borrow()) {
            return writer.send_eof().err_tip(|| "Failed to send EOF for zero digest");
        }

        let gcs_path = self.make_gcs_path(&key);
        
        // Calculate end byte if length is specified
        let end_byte = length.map(|len| offset + len - 1);
        
        // Use the retrier to handle transient failures
        self.retrier.retry(unfold((writer, offset), move |(writer, current_offset)| async move {
            let response = self.client
                .read_object()
                .bucket(&self.bucket)
                .object(&gcs_path)
                .read_offset(current_offset)
                .set_read_limit(end_byte.map(|end| end - current_offset + 1))
                .send()
                .await;

            match response {
                Ok(response) => {
                    let mut stream = response.into_inner();
                    
                    while let Some(chunk_result) = stream.message().await {
                        match chunk_result {
                            Ok(chunk) => {
                                if let Some(data) = chunk.chunk_data {
                                    if data.is_empty() {
                                        continue; // Skip empty chunks
                                    }
                                    if let Err(e) = writer.send(data).await {
                                        return Some((RetryResult::Err(make_err!(
                                            Code::Internal,
                                            "Failed to write data chunk: {}", e
                                        )), (writer, current_offset)));
                                    }
                                }
                            }
                            Err(e) => {
                                return Some((RetryResult::Retry(make_err!(
                                    Code::Aborted,
                                    "Failed to read chunk: {}", e
                                )), (writer, current_offset)));
                            }
                        }
                    }
                    
                    if let Err(e) = writer.send_eof() {
                        return Some((RetryResult::Err(make_err!(
                            Code::Internal,
                            "Failed to send EOF: {}", e
                        )), (writer, current_offset)));
                    }
                    
                    Some((RetryResult::Ok(()), (writer, current_offset)))
                }
                Err(status) if status.code() == tonic::Code::NotFound => {
                    Some((RetryResult::Err(make_err!(
                        Code::NotFound,
                        "Object not found: {}", gcs_path
                    )), (writer, current_offset)))
                }
                Err(e) => Some((RetryResult::Retry(make_err!(
                    Code::Aborted,
                    "Failed to read object: {}", e
                )), (writer, current_offset)))
            }
        })).await
    }

    fn inner_store(&self, _digest: Option<StoreKey>) -> &'_ dyn StoreDriver {
        self
    }

    fn as_any<'a>(&'a self) -> &'a (dyn std::any::Any + Sync + Send + 'static) {
        self
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Sync + Send + 'static> {
        self
    }
}

#[async_trait]
impl<I, NowFn> HealthStatusIndicator for GcsStore<NowFn>
where
    I: InstantWrapper,
    NowFn: Fn() -> I + Send + Sync + Unpin + 'static,
{
    fn get_name(&self) -> &'static str {
        "GcsStore"
    }

    /// Checks the health of the GCS connection.
    ///
    /// Implementation steps:
    /// 1. Try to list a small number of objects
    /// 2. Check connection to GCS
    /// 3. Return appropriate health status
    async fn check_health(&self, namespace: Cow<'static, str>) -> HealthStatus {
        StoreDriver::check_health(Pin::new(self), namespace).await
    }
}

#[cfg(test)]
mod tests {
    // Test implementation steps:
    // 1. Mock GCS client for unit tests
    // 2. Test all main operations:
    //    - new() constructor
    //    - has_with_results
    //    - update
    //    - get_part
    // 3. Test error cases and retries
    // 4. Test zero digest handling
    // 5. Test multipart uploads
    // 6. Test expired object handling
} 