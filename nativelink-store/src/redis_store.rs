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

use async_trait::async_trait;
use bytes::Bytes;
use nativelink_error::{error_if, make_err, Code, Error, ResultExt};
use nativelink_util::buf_channel::{DropCloserReadHalf, DropCloserWriteHalf};
use nativelink_util::common::DigestInfo;
use nativelink_util::health_utils::{HealthRegistryBuilder, HealthStatus, HealthStatusIndicator};
use nativelink_util::metrics_utils::{Collector, CollectorState, MetricsComponent, Registry};
use nativelink_util::store_trait::{Store, UploadSizeInfo};
use redis::aio::{ConnectionLike, ConnectionManager};
use redis::AsyncCommands;

use crate::cas_utils::is_zero_digest;

fn digest_to_key(digest: &DigestInfo) -> String {
    format!("{}-{}", digest.hash_str(), digest.size_bytes)
}

pub struct RedisStore<T: ConnectionLike + Unpin + Clone + Send + Sync = ConnectionManager> {
    conn: T,
    temp_name_generator_fn: fn() -> String,
}

impl RedisStore {
    pub async fn new(
        config: &nativelink_config::stores::RedisStore,
    ) -> Result<RedisStore<ConnectionManager>, Error> {
        // Note: Currently only one connection is supported.
        error_if!(
            config.addresses.len() != 1,
            "Only one address is supported for Redis store"
        );

        let conn = redis::Client::open(config.addresses[0].clone())
            .map_err(from_redis_err)?
            .get_connection_manager()
            .await
            .map_err(from_redis_err)?;

        Ok(RedisStore {
            conn,
            temp_name_generator_fn: || uuid::Uuid::new_v4().to_string(),
        })
    }
}

impl<T: ConnectionLike + Unpin + Clone + Send + Sync> RedisStore<T> {
    pub fn new_with_conn_and_name_generator(
        conn: T,
        temp_name_generator_fn: fn() -> String,
    ) -> Result<RedisStore<T>, Error> {
        Ok(RedisStore {
            conn,
            temp_name_generator_fn: temp_name_generator_fn,
        })
    }
}

#[async_trait]
impl<T: ConnectionLike + Unpin + Clone + Send + Sync + 'static> Store for RedisStore<T> {
    async fn has_with_results(
        self: Pin<&Self>,
        digests: &[DigestInfo],
        results: &mut [Option<usize>],
    ) -> Result<(), Error> {
        if digests.len() == 1 && is_zero_digest(&digests[0]) {
            results[0] = Some(0);
            return Ok(());
        }
        let mut conn = self.conn.clone();

        let mut pipe = redis::pipe();
        pipe.atomic();

        let mut zero_digest_indexes = Vec::new();
        digests.iter().enumerate().for_each(|(index, digest)| {
            if is_zero_digest(digest) {
                zero_digest_indexes.push(index);
            }

            pipe.strlen(digest_to_key(digest));
        });

        let digest_sizes = pipe
            .query_async::<_, Vec<usize>>(&mut conn)
            .await
            .map_err(from_redis_err)?;

        error_if!(
            digest_sizes.len() != results.len(),
            "Mismatch in digest sizes and results length"
        );

        digest_sizes
            .into_iter()
            .zip(results.iter_mut())
            .for_each(|(size, result)| {
                *result = if size == 0 { None } else { Some(size as usize) };
            });

        zero_digest_indexes.into_iter().for_each(|index| {
            results[index] = Some(0);
        });

        Ok(())
    }

    async fn update(
        self: Pin<&Self>,
        digest: DigestInfo,
        mut reader: DropCloserReadHalf,
        _upload_size: UploadSizeInfo,
    ) -> Result<(), Error> {
        let temp_key = format!("temp-{}", (self.temp_name_generator_fn)());
        let mut conn = self.conn.clone();
        let mut pipe = redis::pipe();
        pipe.atomic();

        'outer: loop {
            let mut first_run = true;
            while first_run || !reader.is_empty() {
                let chunk = reader
                    .recv()
                    .await
                    .err_tip(|| "Failed to reach chunk in update in redis store")?;
                if chunk.is_empty() {
                    if is_zero_digest(&digest) {
                        return Ok(());
                    }
                    break 'outer;
                }
                pipe.cmd("APPEND").arg(&temp_key).arg(&chunk[..]);
                first_run = false;
                // Give other tasks a chance to run to populate the buffer
                // if possible.
                tokio::task::yield_now().await;
            }
        }

        pipe.query_async(&mut conn).await.map_err(from_redis_err)?;

        conn.rename(temp_key, digest_to_key(&digest))
            .await
            .map_err(from_redis_err)?;
        Ok(())
    }

    async fn get_part_ref(
        self: Pin<&Self>,
        digest: DigestInfo,
        writer: &mut DropCloserWriteHalf,
        offset: usize,
        length: Option<usize>,
    ) -> Result<(), Error> {
        if is_zero_digest(&digest) {
            writer
                .send_eof()
                .err_tip(|| "Failed to send zero EOF in redis store get_part_ref")?;
            return Ok(());
        }

        let mut conn = self.conn.clone();
        if length == Some(0) {
            let exists = conn
                .exists::<_, bool>(digest_to_key(&digest))
                .await
                .map_err(from_redis_err)?;
            if !exists {
                return Err(make_err!(
                    Code::NotFound,
                    "Data not found in Redis store for digest: {}",
                    digest_to_key(&digest)
                ));
            }
            writer
                .send_eof()
                .err_tip(|| "Failed to write EOF in redis store get_part_ref")?;
            return Ok(());
        }

        let mut data_received = 0;
        let mut current_start = offset as isize;
        let max_length = length.unwrap_or(isize::MAX as usize);
        let end_position = isize::try_from(
            offset.saturating_add(max_length)
        )
        .err_tip(|| format!("Cannot convert offset to isize in redis store get_part_ref for {offset} + {length:?}"))?;

        const CHUNK_SIZE: isize = 64 * 1024;
        loop {
            let current_end =
                std::cmp::min(current_start.saturating_add(CHUNK_SIZE), end_position) - 1;
            let chunk = conn
                .getrange::<_, Bytes>(digest_to_key(&digest), current_start, current_end)
                .await
                .map_err(from_redis_err)?;

            if chunk.is_empty() {
                writer
                    .send_eof()
                    .err_tip(|| "Failed to write EOF in redis store get_part")?;
                break;
            }

            let was_partial_data = chunk.len() as isize != current_end + 1 - current_start;
            current_start += chunk.len() as isize;
            data_received += chunk.len();
            writer
                .send(chunk)
                .await
                .err_tip(|| "Failed to write data in Redis store")?;

            if data_received == max_length || was_partial_data {
                writer
                    .send_eof()
                    .err_tip(|| "Failed to write EOF in redis store get_part")?;

                break;
            }

            error_if!(
                data_received > max_length,
                "Data received exceeds requested length"
            );
        }

        Ok(())
    }

    fn inner_store(&self, _digest: Option<DigestInfo>) -> &'_ dyn Store {
        self
    }

    fn inner_store_arc(self: Arc<Self>, _digest: Option<DigestInfo>) -> Arc<dyn Store> {
        self
    }

    fn as_any(&self) -> &(dyn std::any::Any + Sync + Send) {
        self
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Sync + Send> {
        self
    }

    fn register_metrics(self: Arc<Self>, registry: &mut Registry) {
        registry.register_collector(Box::new(Collector::new(&self)));
    }

    fn register_health(self: Arc<Self>, registry: &mut HealthRegistryBuilder) {
        registry.register_indicator(self);
    }
}

impl<T: ConnectionLike + Unpin + Clone + Send + Sync + 'static> MetricsComponent for RedisStore<T> {
    fn gather_metrics(&self, _c: &mut CollectorState) {}
}

#[async_trait]
impl<T: ConnectionLike + ConnectionLike + Unpin + Clone + Send + Sync + 'static>
    HealthStatusIndicator for RedisStore<T>
{
    fn get_name(&self) -> &'static str {
        "RedisStore"
    }

    async fn check_health(&self, namespace: Cow<'static, str>) -> HealthStatus {
        Store::check_health(Pin::new(self), namespace).await
    }
}

fn from_redis_err(call_res: redis::RedisError) -> Error {
    make_err!(Code::Internal, "Redis Error: {call_res}")
}
