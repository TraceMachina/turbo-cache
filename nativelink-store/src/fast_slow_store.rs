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

use std::borrow::BorrowMut;
use std::cmp::{max, min};
use std::ops::Range;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use futures::{join, FutureExt};
use nativelink_config::stores::FastSlowSpec;
use nativelink_error::{make_err, Code, Error, ResultExt};
use nativelink_metric::MetricsComponent;
use nativelink_util::buf_channel::{
    make_buf_channel_pair, DropCloserReadHalf, DropCloserWriteHalf,
};
use nativelink_util::fs;
use nativelink_util::health_utils::{default_health_status_indicator, HealthStatusIndicator};
use nativelink_util::store_trait::{
    slow_update_store_with_file, Store, StoreDriver, StoreKey, StoreLike, StoreOptimizations,
    UploadSizeInfo,
};

// TODO(blaise.bruer) This store needs to be evaluated for more efficient memory usage,
// there are many copies happening internally.

// TODO(blaise.bruer) We should consider copying the data in the background to allow the
// client to hang up while the data is buffered. An alternative is to possibly make a
// "BufferedStore" that could be placed on the "slow" store that would hang up early
// if data is in the buffer.
#[derive(MetricsComponent)]
pub struct FastSlowStore {
    #[metric(group = "fast_store")]
    fast_store: Store,
    #[metric(group = "slow_store")]
    slow_store: Store,
    weak_self: Weak<Self>,
    #[metric]
    metrics: FastSlowStoreMetrics,
}

impl FastSlowStore {
    pub fn new(_spec: &FastSlowSpec, fast_store: Store, slow_store: Store) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| Self {
            fast_store,
            slow_store,
            weak_self: weak_self.clone(),
            metrics: FastSlowStoreMetrics::default(),
        })
    }

    pub const fn fast_store(&self) -> &Store {
        &self.fast_store
    }

    pub const fn slow_store(&self) -> &Store {
        &self.slow_store
    }

    pub fn get_arc(&self) -> Option<Arc<Self>> {
        self.weak_self.upgrade()
    }

    /// Ensure our fast store is populated. This should be kept as a low
    /// cost function. Since the data itself is shared and not copied it should be fairly
    /// low cost to just discard the data, but does cost a few mutex locks while
    /// streaming.
    pub async fn populate_fast_store(&self, key: StoreKey<'_>) -> Result<(), Error> {
        let maybe_size_info = self
            .fast_store
            .has(key.borrow())
            .await
            .err_tip(|| "While querying in populate_fast_store")?;
        if maybe_size_info.is_some() {
            return Ok(());
        }
        // TODO(blaise.bruer) This is extremely inefficient, since we are just trying
        // to send the stream to /dev/null. Maybe we could instead make a version of
        // the stream that can send to the drain more efficiently?
        let (tx, mut rx) = make_buf_channel_pair();
        let drain_fut = async move {
            while !rx.recv().await?.is_empty() {}
            Ok(())
        };
        let (drain_res, get_res) = join!(drain_fut, StoreDriver::get(Pin::new(self), key, tx));
        get_res.err_tip(|| "Failed to populate()").merge(drain_res)
    }

    /// Returns the range of bytes that should be sent given a slice bounds
    /// offset so the output range maps the `received_range.start` to 0.
    // TODO(allada) This should be put into utils, as this logic is used
    // elsewhere in the code.
    pub fn calculate_range(
        received_range: &Range<u64>,
        send_range: &Range<u64>,
    ) -> Result<Option<Range<usize>>, Error> {
        // Protect against subtraction overflow.
        if received_range.start >= received_range.end {
            return Ok(None);
        }

        let start = max(received_range.start, send_range.start);
        let end = min(received_range.end, send_range.end);
        if received_range.contains(&start) && received_range.contains(&(end - 1)) {
            // Offset both to the start of the received_range.
            let calculated_range_start = usize::try_from(start - received_range.start)
                .err_tip(|| "Could not convert (start - received_range.start) to usize")?;
            let calculated_range_end = usize::try_from(end - received_range.start)
                .err_tip(|| "Could not convert (end - received_range.start) to usize")?;
            Ok(Some(calculated_range_start..calculated_range_end))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl StoreDriver for FastSlowStore {
    async fn has_with_results(
        self: Pin<&Self>,
        key: &[StoreKey<'_>],
        results: &mut [Option<u64>],
    ) -> Result<(), Error> {
        // If our slow store is a noop store, it'll always return a 404,
        // so only check the fast store in such case.
        let slow_store = self.slow_store.inner_store::<StoreKey<'_>>(None);
        if slow_store.optimized_for(StoreOptimizations::NoopDownloads) {
            return self.fast_store.has_with_results(key, results).await;
        }
        // Only check the slow store because if it's not there, then something
        // down stream might be unable to get it.  This should not affect
        // workers as they only use get() and a CAS can use an
        // ExistenceCacheStore to avoid the bottleneck.
        self.slow_store.has_with_results(key, results).await
    }

    async fn update(
        self: Pin<&Self>,
        key: StoreKey<'_>,
        mut reader: DropCloserReadHalf,
        size_info: UploadSizeInfo,
    ) -> Result<(), Error> {
        // If either one of our stores is a noop store, bypass the multiplexing
        // and just use the store that is not a noop store.
        let slow_store = self.slow_store.inner_store(Some(key.borrow()));
        if slow_store.optimized_for(StoreOptimizations::NoopUpdates) {
            return self.fast_store.update(key, reader, size_info).await;
        }
        let fast_store = self.fast_store.inner_store(Some(key.borrow()));
        if fast_store.optimized_for(StoreOptimizations::NoopUpdates) {
            return self.slow_store.update(key, reader, size_info).await;
        }

        let (mut fast_tx, fast_rx) = make_buf_channel_pair();
        let (mut slow_tx, slow_rx) = make_buf_channel_pair();

        let data_stream_fut = async move {
            loop {
                let buffer = reader
                    .recv()
                    .await
                    .err_tip(|| "Failed to read buffer in fastslow store")?;
                if buffer.is_empty() {
                    // EOF received.
                    fast_tx.send_eof().err_tip(|| {
                        "Failed to write eof to fast store in fast_slow store update"
                    })?;
                    slow_tx
                        .send_eof()
                        .err_tip(|| "Failed to write eof to writer in fast_slow store update")?;
                    return Result::<(), Error>::Ok(());
                }

                let (fast_result, slow_result) =
                    join!(fast_tx.send(buffer.clone()), slow_tx.send(buffer));
                fast_result
                    .map_err(|e| {
                        make_err!(
                            Code::Internal,
                            "Failed to send message to fast_store in fast_slow_store {:?}",
                            e
                        )
                    })
                    .merge(slow_result.map_err(|e| {
                        make_err!(
                            Code::Internal,
                            "Failed to send message to slow_store in fast_slow store {:?}",
                            e
                        )
                    }))?;
            }
        };

        let fast_store_fut = self.fast_store.update(key.borrow(), fast_rx, size_info);
        let slow_store_fut = self.slow_store.update(key.borrow(), slow_rx, size_info);

        let (data_stream_res, fast_res, slow_res) =
            join!(data_stream_fut, fast_store_fut, slow_store_fut);
        data_stream_res.merge(fast_res).merge(slow_res)?;
        Ok(())
    }

    /// FastSlowStore has optimiations for dealing with files.
    fn optimized_for(&self, optimization: StoreOptimizations) -> bool {
        optimization == StoreOptimizations::FileUpdates
    }

    /// Optimized variation to consume the file if one of the stores is a
    /// filesystem store. This makes the operation a move instead of a copy
    /// dramatically increasing performance for large files.
    async fn update_with_whole_file(
        self: Pin<&Self>,
        key: StoreKey<'_>,
        mut file: fs::ResumeableFileSlot,
        upload_size: UploadSizeInfo,
    ) -> Result<Option<fs::ResumeableFileSlot>, Error> {
        if self
            .fast_store
            .optimized_for(StoreOptimizations::FileUpdates)
        {
            if !self
                .slow_store
                .optimized_for(StoreOptimizations::NoopUpdates)
            {
                slow_update_store_with_file(
                    self.slow_store.as_store_driver_pin(),
                    key.borrow(),
                    &mut file,
                    upload_size,
                )
                .await
                .err_tip(|| "In FastSlowStore::update_with_whole_file slow_store")?;
            }
            return self
                .fast_store
                .update_with_whole_file(key, file, upload_size)
                .await;
        }

        if self
            .slow_store
            .optimized_for(StoreOptimizations::FileUpdates)
        {
            if !self
                .fast_store
                .optimized_for(StoreOptimizations::NoopUpdates)
            {
                slow_update_store_with_file(
                    self.fast_store.as_store_driver_pin(),
                    key.borrow(),
                    &mut file,
                    upload_size,
                )
                .await
                .err_tip(|| "In FastSlowStore::update_with_whole_file fast_store")?;
            }
            return self
                .slow_store
                .update_with_whole_file(key, file, upload_size)
                .await;
        }

        slow_update_store_with_file(self, key, &mut file, upload_size)
            .await
            .err_tip(|| "In FastSlowStore::update_with_whole_file")?;
        Ok(Some(file))
    }

    async fn get_part(
        self: Pin<&Self>,
        key: StoreKey<'_>,
        writer: &mut DropCloserWriteHalf,
        offset: u64,
        length: Option<u64>,
    ) -> Result<(), Error> {
        // TODO(blaise.bruer) Investigate if we should maybe ignore errors here instead of
        // forwarding the up.
        if self.fast_store.has(key.borrow()).await?.is_some() {
            self.metrics
                .fast_store_hit_count
                .fetch_add(1, Ordering::Acquire);
            self.fast_store
                .get_part(key, writer.borrow_mut(), offset, length)
                .await?;
            self.metrics
                .fast_store_downloaded_bytes
                .fetch_add(writer.get_bytes_written(), Ordering::Acquire);
            return Ok(());
        }

        let sz = self
            .slow_store
            .has(key.borrow())
            .await
            .err_tip(|| "Failed to run has() on slow store")?
            .ok_or_else(|| {
                make_err!(
                    Code::NotFound,
                    "Object {} not found in either fast or slow store",
                    key.as_str()
                )
            })?;
        self.metrics
            .slow_store_hit_count
            .fetch_add(1, Ordering::Acquire);

        let send_range = offset..length.map_or(u64::MAX, |length| length + offset);
        let mut bytes_received: u64 = 0;

        let (mut fast_tx, fast_rx) = make_buf_channel_pair();
        let (slow_tx, mut slow_rx) = make_buf_channel_pair();
        let data_stream_fut = async move {
            let mut writer_pin = Pin::new(writer);
            loop {
                let output_buf = slow_rx
                    .recv()
                    .await
                    .err_tip(|| "Failed to read data data buffer from slow store")?;
                if output_buf.is_empty() {
                    // Write out our EOF.
                    // We are dropped as soon as we send_eof to writer_pin, so
                    // we wait until we've finished all of our joins to do that.
                    let fast_res = fast_tx.send_eof();
                    return Ok::<_, Error>((fast_res, writer_pin));
                }
                let output_buf_len = u64::try_from(output_buf.len())
                    .err_tip(|| "Could not output_buf.len() to u64")?;
                self.metrics
                    .slow_store_downloaded_bytes
                    .fetch_add(output_buf_len, Ordering::Acquire);

                let writer_fut = if let Some(range) = Self::calculate_range(
                    &(bytes_received..bytes_received + output_buf_len),
                    &send_range,
                )? {
                    writer_pin.send(output_buf.slice(range)).right_future()
                } else {
                    futures::future::ready(Ok(())).left_future()
                };
                bytes_received += output_buf_len;

                let (fast_tx_res, writer_res) = join!(fast_tx.send(output_buf), writer_fut);
                fast_tx_res.err_tip(|| "Failed to write to fast store in fast_slow store")?;
                writer_res.err_tip(|| "Failed to write result to writer in fast_slow store")?;
            }
        };

        let slow_store_fut = self.slow_store.get(key.borrow(), slow_tx);
        let fast_store_fut =
            self.fast_store
                .update(key.borrow(), fast_rx, UploadSizeInfo::ExactSize(sz));

        let (data_stream_res, slow_res, fast_res) =
            join!(data_stream_fut, slow_store_fut, fast_store_fut);
        match data_stream_res {
            Ok((fast_eof_res, mut writer_pin)) =>
            // Sending the EOF will drop us almost immediately in bytestream_server
            // so we perform it as the very last action in this method.
            {
                fast_eof_res
                    .merge(fast_res)
                    .merge(slow_res)
                    .merge(writer_pin.send_eof())
            }
            Err(err) => fast_res.merge(slow_res).merge(Err(err)),
        }
    }

    fn inner_store(&self, _key: Option<StoreKey>) -> &dyn StoreDriver {
        self
    }

    fn as_any<'a>(&'a self) -> &'a (dyn std::any::Any + Sync + Send + 'static) {
        self
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Sync + Send + 'static> {
        self
    }
}

#[derive(Default, MetricsComponent)]
struct FastSlowStoreMetrics {
    #[metric(help = "Hit count for the fast store")]
    fast_store_hit_count: AtomicU64,
    #[metric(help = "Downloaded bytes from the fast store")]
    fast_store_downloaded_bytes: AtomicU64,
    #[metric(help = "Hit count for the slow store")]
    slow_store_hit_count: AtomicU64,
    #[metric(help = "Downloaded bytes from the slow store")]
    slow_store_downloaded_bytes: AtomicU64,
}

default_health_status_indicator!(FastSlowStore);
