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
use bytes::Bytes;
use futures::stream::unfold;
use futures::TryStreamExt;
use nativelink_config::stores::GcsSpec;
use nativelink_error::{make_err, Code, Error, ResultExt};
use nativelink_metric::MetricsComponent;
use nativelink_util::buf_channel::{
    make_buf_channel_pair, DropCloserReadHalf, DropCloserWriteHalf,
};
use nativelink_util::health_utils::{HealthStatus, HealthStatusIndicator};
use nativelink_util::instant_wrapper::InstantWrapper;
use nativelink_util::retry::{Retrier, RetryResult};
use nativelink_util::store_trait::{StoreDriver, StoreKey, UploadSizeInfo};
use rand::rngs::OsRng;
use rand::Rng;
use tokio::time::sleep;
use tracing::{error, info};

use crate::cas_utils::is_zero_digest;
use crate::gcs_client::client::{GcsClient, ObjectPath};

// Constants for GCS operations
// Unlike what is specified in the docs, there is a slight discrepancy between
// the chunk and multipart sizes limit. The chunk size is recommended to be 8MB
// but the gRPC connection can't handle the size greater than 4MB.
// Also, we are keeping it slightly below the 4MB limit to make sure we don't
// exceed the limit when some metadata is added to the request. It was observed
// that an additional 15 bytes were added to the request size.
const MIN_MULTIPART_SIZE: u64 = 4 * 1024 * 1000; // < 4MB
const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1000; // < 4 MiB
const DEFAULT_MAX_CONCURRENT_UPLOADS: usize = 10;
const DEFAULT_MAX_RETRY_BUFFER_SIZE: usize = 4 * 1024 * 1000; // < MiB

/// The main Google Cloud Storage implementation.
#[derive(MetricsComponent)]
pub struct GcsStore<NowFn> {
    client: Arc<GcsClient>,
    now_fn: NowFn,
    #[metric(help = "The bucket name for the GCS store")]
    bucket: String,
    #[metric(help = "The key prefix for the GCS store")]
    key_prefix: String,
    retrier: Retrier,
    #[metric(help = "The number of seconds to consider an object expired")]
    consider_expired_after_s: i64,
    #[metric(help = "The number of bytes to buffer for retrying requests")]
    max_retry_buffer_size: usize,
    #[metric(help = "The size of chunks for resumable uploads")]
    chunk_size: usize,
    #[metric(help = "The number of concurrent uploads allowed")]
    max_concurrent_uploads: usize,
}

impl<I, NowFn> GcsStore<NowFn>
where
    I: InstantWrapper,
    NowFn: Fn() -> I + Send + Sync + Unpin + 'static,
{
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

        let client = GcsClient::new(spec, jitter_fn.clone()).await?;

        Self::new_with_client_and_jitter(spec, client, jitter_fn, now_fn)
    }

    pub fn new_with_client_and_jitter(
        spec: &GcsSpec,
        gcs_client: GcsClient,
        jitter_fn: Arc<dyn Fn(Duration) -> Duration + Send + Sync>,
        now_fn: NowFn,
    ) -> Result<Arc<Self>, Error> {
        Ok(Arc::new(Self {
            client: Arc::new(gcs_client),
            now_fn,
            bucket: spec.bucket.clone(),
            key_prefix: spec.key_prefix.as_ref().unwrap_or(&String::new()).clone(),
            retrier: Retrier::new(
                Arc::new(|duration| Box::pin(sleep(duration))),
                jitter_fn,
                spec.retry.clone(),
            ),
            consider_expired_after_s: i64::from(spec.consider_expired_after_s),
            max_retry_buffer_size: spec
                .max_retry_buffer_per_request
                .unwrap_or(DEFAULT_MAX_RETRY_BUFFER_SIZE),
            chunk_size: spec
                .resumable_chunk_size
                .unwrap_or(MAX_CHUNK_SIZE)
                .min(MAX_CHUNK_SIZE),
            max_concurrent_uploads: spec
                .max_concurrent_uploads
                .unwrap_or(DEFAULT_MAX_CONCURRENT_UPLOADS),
        }))
    }

    fn make_object_path(&self, key: &StoreKey<'_>) -> String {
        format!("{}{}", self.key_prefix, key.as_str())
    }

    pub async fn has(self: Pin<&Self>, digest: &StoreKey<'_>) -> Result<Option<u64>, Error> {
        let object = ObjectPath::new(self.bucket.clone(), &self.make_object_path(digest));

        let client = self.client.clone();
        let consider_expired_after_s = self.consider_expired_after_s;
        let now_fn = &self.now_fn;

        self.retrier
            .retry(futures::stream::unfold(
                object.clone(),
                move |object_path| {
                    let client = client.clone();

                    async move {
                        let result = client.read_object_metadata(object_path.clone()).await;

                        match result {
                            Ok(Some(object)) => {
                                if consider_expired_after_s > 0 {
                                    if let Some(update_time) = object.update_time {
                                        let now_s = now_fn().unix_timestamp() as i64;
                                        if update_time.seconds + consider_expired_after_s <= now_s {
                                            return Some((RetryResult::Ok(None), object_path));
                                        }
                                    }
                                }
                                Some((RetryResult::Ok(Some(object.size as u64)), object_path))
                            }
                            Ok(None) => Some((RetryResult::Ok(None), object_path)),
                            Err(e) => Some((RetryResult::Retry(e), object_path)),
                        }
                    }
                },
            ))
            .await
    }
}

#[async_trait]
impl<I, NowFn> StoreDriver for GcsStore<NowFn>
where
    I: InstantWrapper,
    NowFn: Fn() -> I + Send + Sync + Unpin + 'static,
{
    async fn has_with_results(
        self: Pin<&Self>,
        keys: &[StoreKey<'_>],
        results: &mut [Option<u64>],
    ) -> Result<(), Error> {
        use futures::stream::FuturesUnordered;

        keys.iter()
            .zip(results.iter_mut())
            .map(|(key, result)| async move {
                if is_zero_digest(key.borrow()) {
                    *result = Some(0);
                    return Ok::<_, Error>(());
                }
                *result = self.has(key).await?;
                Ok::<_, Error>(())
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect()
            .await
    }

    async fn update(
        self: Pin<&Self>,
        digest: StoreKey<'_>,
        mut reader: DropCloserReadHalf,
        upload_size: UploadSizeInfo,
    ) -> Result<(), Error> {
        let object = ObjectPath::new(self.bucket.clone(), &self.make_object_path(&digest));

        if let UploadSizeInfo::ExactSize(0) = upload_size {
            return Ok(());
        }

        let max_size = match upload_size {
            UploadSizeInfo::ExactSize(sz) | UploadSizeInfo::MaxSize(sz) => sz,
        };

        // For small files (< 4MB) use simple upload
        if max_size < MIN_MULTIPART_SIZE && matches!(upload_size, UploadSizeInfo::ExactSize(_)) {
            let UploadSizeInfo::ExactSize(sz) = upload_size else {
                unreachable!("upload_size must be ExactSize here");
            };

            reader.set_max_recent_data_size(
                u64::try_from(self.max_retry_buffer_size)
                    .err_tip(|| "Could not convert max_retry_buffer_size to u64")?,
            );

            return self.retrier
                .retry(unfold(reader, move |mut reader| {
                    let client = Arc::clone(&self.client);
                    let object = object.clone();

                    async move {
                        let (mut tx, rx) = make_buf_channel_pair();

                        let result = {
                            let reader_ref = &mut reader;
                            let (upload_res, bind_res) = tokio::join!(
                            async {
                                client
                                    .simple_upload(object.clone(), rx, sz as i64)
                                    .await
                                    .map_err(|e| make_err!(Code::Aborted, "{:?}", e))
                            },
                            async {
                                tx.bind_buffered(reader_ref).await
                            }
                        );

                            upload_res
                                .and(bind_res)
                                .err_tip(|| "Failed to upload object in single chunk")
                        };

                        match result {
                            Ok(()) => Some((RetryResult::Ok(()), reader)),
                            Err(mut err) => {
                                err.code = Code::Aborted;
                                let bytes_received = reader.get_bytes_received();

                                if let Err(try_reset_err) = reader.try_reset_stream() {
                                    error!(
                                    ?bytes_received,
                                    err = ?try_reset_err,
                                    "Unable to reset stream after failed upload"
                                );
                                    Some((
                                        RetryResult::Err(err
                                            .merge(try_reset_err)
                                            .append(format!(
                                                "Failed to retry upload with {bytes_received} bytes received"
                                            ))),
                                        reader,
                                    ))
                                } else {
                                    let err = err.append(format!(
                                        "Retry on upload happened with {bytes_received} bytes received"
                                    ));
                                    info!(?err, ?bytes_received, "Retryable GCS error");
                                    Some((RetryResult::Retry(err), reader))
                                }
                            }
                        }
                    }
                }))
                .await;
        }

        // For larger files, use resumable upload with streaming
        reader.set_max_recent_data_size(
            u64::try_from(self.max_retry_buffer_size)
                .err_tip(|| "Could not convert max_retry_buffer_size to u64")?,
        );

        self.retrier
            .retry(unfold(reader, move |mut reader| {
                let client = Arc::clone(&self.client);
                let object = object.clone();

                async move {
                    let (mut tx, rx) = make_buf_channel_pair();

                    let result = {
                        let reader_ref = &mut reader;
                        let (upload_res, bind_res) = tokio::join!(
                        async {
                            client
                                .resumable_upload(object.clone(), rx, max_size as i64)
                                .await
                                .map_err(|e| make_err!(Code::Aborted, "{:?}", e))
                        },
                        async {
                            tx.bind_buffered(reader_ref).await
                        }
                    );

                        upload_res
                            .and(bind_res)
                            .err_tip(|| "Failed to upload object using resumable upload")
                    };

                    match result {
                        Ok(()) => Some((RetryResult::Ok(()), reader)),
                        Err(mut err) => {
                            err.code = Code::Aborted;
                            let bytes_received = reader.get_bytes_received();

                            if let Err(try_reset_err) = reader.try_reset_stream() {
                                error!(
                                ?bytes_received,
                                err = ?try_reset_err,
                                "Unable to reset stream after failed upload"
                            );
                                Some((
                                    RetryResult::Err(err
                                        .merge(try_reset_err)
                                        .append(format!(
                                            "Failed to retry upload with {bytes_received} bytes received"
                                        ))),
                                    reader,
                                ))
                            } else {
                                let err = err.append(format!(
                                    "Retry on upload happened with {bytes_received} bytes received"
                                ));
                                info!(?err, ?bytes_received, "Retryable GCS error");
                                Some((RetryResult::Retry(err), reader))
                            }
                        }
                    }
                }
            }))
            .await
    }

    async fn get_part(
        self: Pin<&Self>,
        key: StoreKey<'_>,
        writer: &mut DropCloserWriteHalf,
        offset: u64,
        length: Option<u64>,
    ) -> Result<(), Error> {
        if is_zero_digest(key.borrow()) {
            writer
                .send_eof()
                .err_tip(|| "Failed to send zero EOF in GCS store get_part")?;
            return Ok(());
        }

        let object = ObjectPath::new(self.bucket.clone(), &self.make_object_path(&key));

        let client = Arc::clone(&self.client);

        self.retrier
            .retry(unfold(writer, move |writer| {
                let client = client.clone();
                let object = object.clone();
                async move {
                    let result: Result<(), Error> = async {
                        let data = client
                            .read_object_content(
                                object,
                                offset as i64,
                                length.map(|len| offset as i64 + len as i64),
                            )
                            .await?;

                        if !data.is_empty() {
                            writer.send(Bytes::from(data)).await.map_err(|e| {
                                make_err!(Code::Aborted, "Failed to send data to writer: {:?}", e)
                            })?;
                        }

                        writer.send_eof().map_err(|e| {
                            make_err!(Code::Aborted, "Failed to send EOF to writer: {:?}", e)
                        })?;
                        Ok(())
                    }
                    .await;

                    match result {
                        Ok(()) => Some((RetryResult::Ok(()), writer)),
                        Err(e) => {
                            if e.code == Code::NotFound {
                                Some((RetryResult::Err(e), writer))
                            } else {
                                Some((RetryResult::Retry(e), writer))
                            }
                        }
                    }
                }
            }))
            .await
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

    async fn check_health(&self, namespace: Cow<'static, str>) -> HealthStatus {
        StoreDriver::check_health(Pin::new(self), namespace).await
    }
}
