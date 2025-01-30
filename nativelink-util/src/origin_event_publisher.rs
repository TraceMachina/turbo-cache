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

use bytes::BytesMut;
use futures::{future, FutureExt};
use nativelink_proto::com::github::trace_machina::nativelink::events::{OriginEvent, OriginEvents};
use prost::Message;
use tokio::sync::{broadcast, mpsc};
use tracing::error;
use uuid::Uuid;

use crate::origin_event::get_node_id;
use crate::shutdown_guard::{Priority, ShutdownGuard};
use crate::store_trait::{Store, StoreLike};

/// Publishes origin events to the store.
pub struct OriginEventPublisher {
    store: Store,
    rx: mpsc::Receiver<OriginEvent>,
    shutdown_tx: broadcast::Sender<ShutdownGuard>,
}

impl OriginEventPublisher {
    pub const fn new(
        store: Store,
        rx: mpsc::Receiver<OriginEvent>,
        shutdown_tx: broadcast::Sender<ShutdownGuard>,
    ) -> Self {
        Self {
            store,
            rx,
            shutdown_tx,
        }
    }

    /// Runs the origin event publisher.
    pub async fn run(mut self) {
        const MAX_EVENTS_PER_BATCH: usize = 1024;
        let mut batch: Vec<OriginEvent> = Vec::with_capacity(MAX_EVENTS_PER_BATCH);
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let shutdown_fut = shutdown_rx.recv().fuse();
        tokio::pin!(shutdown_fut);
        let shutdown_guard = future::pending().left_future();
        tokio::pin!(shutdown_guard);
        loop {
            tokio::select! {
                biased;
                _ = self.rx.recv_many(&mut batch, MAX_EVENTS_PER_BATCH) => {
                    self.handle_batch(&mut batch).await;
                }
                shutdown_guard_res = &mut shutdown_fut => {
                    tracing::info!("Received shutdown down in origin event publisher");
                    let Ok(mut local_shutdown_guard) = shutdown_guard_res else {
                        tracing::error!("Received shutdown down in origin event publisher but failed to get shutdown guard");
                        return;
                    };
                    shutdown_guard.set(async move {
                        local_shutdown_guard.wait_for(Priority::P0).await;
                    }
                    .right_future());
                }
                () = &mut shutdown_guard => {
                    // All other services with less priority have completed.
                    // We may still need to process any remaining events.
                    while !self.rx.is_empty() {
                        self.rx.recv_many(&mut batch, MAX_EVENTS_PER_BATCH).await;
                        self.handle_batch(&mut batch).await;
                    }
                    return;
                }
            }
        }
    }

    async fn handle_batch(&self, batch: &mut Vec<OriginEvent>) {
        let uuid = Uuid::now_v6(&get_node_id(None));
        let events = OriginEvents {
            // Clippy wants us to use use `mem::take`, but this would
            // move all capacity as well to the new vector. Since it is
            // much more likely that we will have a small number of events
            // in the batch, we prefer to use `drain` and `collect` here,
            // so we only need to allocate the exact amount of memory needed
            // and let the batch vector's capacity be reused.
            #[allow(clippy::drain_collect)]
            events: batch.drain(..).collect(),
        };
        let mut data = BytesMut::new();
        if let Err(e) = events.encode(&mut data) {
            error!("Failed to encode origin events: {}", e);
            return;
        }
        let update_result = self
            .store
            .as_store_driver_pin()
            .update_oneshot(
                format!("OriginEvents:{}", uuid.hyphenated()).into(),
                data.freeze(),
            )
            .await;
        if let Err(err) = update_result {
            error!("Failed to upload origin events: {}", err);
        }
    }
}
