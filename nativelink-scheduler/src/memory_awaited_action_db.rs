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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;
use std::time::Duration;

use async_lock::Mutex;
use futures::{FutureExt, Stream};
use nativelink_config::stores::EvictionPolicy;
use nativelink_error::{error_if, make_err, Code, Error, ResultExt};
use nativelink_metric::MetricsComponent;
use nativelink_util::action_messages::{
    ActionInfo, ActionStage, ActionUniqueKey, ActionUniqueQualifier, OperationId,
};
use nativelink_util::chunked_stream::ChunkedStream;
use nativelink_util::evicting_map::{EvictingMap, LenEntry};
use nativelink_util::instant_wrapper::InstantWrapper;
use nativelink_util::spawn;
use nativelink_util::task::JoinHandleDropGuard;
use tokio::sync::{mpsc, watch, Notify};
use tracing::{event, Level};

use crate::awaited_action_db::{
    AwaitedAction, AwaitedActionDb, AwaitedActionSubscriber, SortedAwaitedAction,
    SortedAwaitedActionState,
};

/// Number of events to process per cycle.
const MAX_ACTION_EVENTS_RX_PER_CYCLE: usize = 1024;

/// Duration to wait before sending client keep alive messages.
const CLIENT_KEEPALIVE_DURATION: Duration = Duration::from_secs(10);

/// Represents a client that is currently listening to an action.
/// When the client is dropped, it will send the `AwaitedAction` to the
/// `event_tx` if there are other cleanups needed.
#[derive(Debug)]
struct ClientAwaitedAction {
    /// The `OperationId` that the client is listening to.
    operation_id: OperationId,

    /// The sender to notify of this struct being dropped.
    event_tx: mpsc::UnboundedSender<ActionEvent>,
}

impl ClientAwaitedAction {
    pub const fn new(
        operation_id: OperationId,
        event_tx: mpsc::UnboundedSender<ActionEvent>,
    ) -> Self {
        Self {
            operation_id,
            event_tx,
        }
    }

    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
}

impl Drop for ClientAwaitedAction {
    fn drop(&mut self) {
        // If we failed to send it means noone is listening.
        let _ = self.event_tx.send(ActionEvent::ClientDroppedOperation(
            self.operation_id.clone(),
        ));
    }
}

/// Trait to be able to use the `EvictingMap` with `ClientAwaitedAction`.
/// Note: We only use `EvictingMap` for a time based eviction, which is
/// why the implementation has fixed default values in it.
impl LenEntry for ClientAwaitedAction {
    #[inline]
    fn len(&self) -> u64 {
        0
    }

    #[inline]
    fn is_empty(&self) -> bool {
        true
    }
}

/// Actions the `AwaitedActionsDb` needs to process.
#[derive(Debug)]
pub(crate) enum ActionEvent {
    /// A client has sent a keep alive message.
    ClientKeepAlive(OperationId),
    /// A client has dropped and pointed to `OperationId`.
    ClientDroppedOperation(OperationId),
}

/// Information required to track an individual client
/// keep alive config and state.
struct ClientInfo<I: InstantWrapper, NowFn: Fn() -> I> {
    /// The client operation id.
    client_operation_id: OperationId,
    /// The last time a keep alive was sent.
    last_keep_alive: I,
    /// The function to get the current time.
    now_fn: NowFn,
    /// The sender to notify of this struct had an event.
    event_tx: mpsc::UnboundedSender<ActionEvent>,
}

/// Subscriber that clients can be used to monitor when `AwaitedActions` change.
pub struct MemoryAwaitedActionSubscriber<I: InstantWrapper, NowFn: Fn() -> I> {
    /// The receiver to listen for changes.
    awaited_action_rx: watch::Receiver<AwaitedAction>,
    /// If a client id is known this is the info needed to keep the client
    /// action alive.
    client_info: Option<ClientInfo<I, NowFn>>,
}

impl<I: InstantWrapper, NowFn: Fn() -> I> MemoryAwaitedActionSubscriber<I, NowFn> {
    fn new(mut awaited_action_rx: watch::Receiver<AwaitedAction>) -> Self {
        awaited_action_rx.mark_changed();
        Self {
            awaited_action_rx,
            client_info: None,
        }
    }

    fn new_with_client(
        mut awaited_action_rx: watch::Receiver<AwaitedAction>,
        client_operation_id: OperationId,
        event_tx: mpsc::UnboundedSender<ActionEvent>,
        now_fn: NowFn,
    ) -> Self
    where
        NowFn: Fn() -> I,
    {
        awaited_action_rx.mark_changed();
        Self {
            awaited_action_rx,
            client_info: Some(ClientInfo {
                client_operation_id,
                last_keep_alive: I::from_secs(0),
                now_fn,
                event_tx,
            }),
        }
    }
}

impl<I, NowFn> AwaitedActionSubscriber for MemoryAwaitedActionSubscriber<I, NowFn>
where
    I: InstantWrapper,
    NowFn: Fn() -> I + Send + Sync + 'static,
{
    async fn changed(&mut self) -> Result<AwaitedAction, Error> {
        let client_operation_id = {
            let changed_fut = self.awaited_action_rx.changed().map(|r| {
                r.map_err(|e| {
                    make_err!(
                        Code::Internal,
                        "Failed to wait for awaited action to change {e:?}"
                    )
                })
            });
            let Some(client_info) = self.client_info.as_mut() else {
                changed_fut.await?;
                return Ok(self.awaited_action_rx.borrow().clone());
            };
            tokio::pin!(changed_fut);
            loop {
                if client_info.last_keep_alive.elapsed() > CLIENT_KEEPALIVE_DURATION {
                    client_info.last_keep_alive = (client_info.now_fn)();
                    // Failing to send just means our receiver dropped.
                    let _ = client_info.event_tx.send(ActionEvent::ClientKeepAlive(
                        client_info.client_operation_id.clone(),
                    ));
                }
                let sleep_fut = (client_info.now_fn)().sleep(CLIENT_KEEPALIVE_DURATION);
                tokio::select! {
                    result = &mut changed_fut => {
                        result?;
                        break;
                    }
                    () = sleep_fut => {
                        // If we haven't received any updates for a while, we should
                        // let the database know that we are still listening to prevent
                        // the action from being dropped.
                    }
                }
            }
            client_info.client_operation_id.clone()
        };
        // At this stage we know that this event is a client request, so we need
        // to populate the client_operation_id.
        let mut awaited_action = self.awaited_action_rx.borrow().clone();
        awaited_action.set_client_operation_id(client_operation_id);
        Ok(awaited_action)
    }

    async fn borrow(&self) -> Result<AwaitedAction, Error> {
        let mut awaited_action = self.awaited_action_rx.borrow().clone();
        if let Some(client_info) = self.client_info.as_ref() {
            awaited_action.set_client_operation_id(client_info.client_operation_id.clone());
        }
        Ok(awaited_action)
    }
}

/// A struct that is used to keep the devloper from trying to
/// return early from a function.
struct NoEarlyReturn;

#[derive(Default, MetricsComponent)]
struct SortedAwaitedActions {
    #[metric(group = "unknown")]
    unknown: BTreeSet<SortedAwaitedAction>,
    #[metric(group = "cache_check")]
    cache_check: BTreeSet<SortedAwaitedAction>,
    #[metric(group = "queued")]
    queued: BTreeSet<SortedAwaitedAction>,
    #[metric(group = "executing")]
    executing: BTreeSet<SortedAwaitedAction>,
    #[metric(group = "completed")]
    completed: BTreeSet<SortedAwaitedAction>,
}

impl SortedAwaitedActions {
    fn btree_for_state(&mut self, state: &ActionStage) -> &mut BTreeSet<SortedAwaitedAction> {
        match state {
            ActionStage::Unknown => &mut self.unknown,
            ActionStage::CacheCheck => &mut self.cache_check,
            ActionStage::Queued => &mut self.queued,
            ActionStage::Executing => &mut self.executing,
            ActionStage::Completed(_) | ActionStage::CompletedFromCache(_) => &mut self.completed,
        }
    }

    fn insert_sort_map_for_stage(
        &mut self,
        stage: &ActionStage,
        sorted_awaited_action: &SortedAwaitedAction,
    ) -> Result<(), Error> {
        let newly_inserted = match stage {
            ActionStage::Unknown => self.unknown.insert(sorted_awaited_action.clone()),
            ActionStage::CacheCheck => self.cache_check.insert(sorted_awaited_action.clone()),
            ActionStage::Queued => self.queued.insert(sorted_awaited_action.clone()),
            ActionStage::Executing => self.executing.insert(sorted_awaited_action.clone()),
            ActionStage::Completed(_) => self.completed.insert(sorted_awaited_action.clone()),
            ActionStage::CompletedFromCache(_) => {
                self.completed.insert(sorted_awaited_action.clone())
            }
        };
        if !newly_inserted {
            return Err(make_err!(
                Code::Internal,
                "Tried to insert an action that was already in the sorted map. This should never happen. {:?} - {:?}",
                stage,
                sorted_awaited_action
            ));
        }
        Ok(())
    }

    fn process_state_changes(
        &mut self,
        old_awaited_action: &AwaitedAction,
        new_awaited_action: &AwaitedAction,
    ) -> Result<(), Error> {
        let btree = self.btree_for_state(&old_awaited_action.state().stage);
        let maybe_sorted_awaited_action = btree.take(&SortedAwaitedAction {
            sort_key: old_awaited_action.sort_key(),
            operation_id: new_awaited_action.operation_id().clone(),
        });

        let Some(sorted_awaited_action) = maybe_sorted_awaited_action else {
            return Err(make_err!(
                Code::Internal,
                "sorted_action_info_hash_keys and action_info_hash_key_to_awaited_action are out of sync - {} - {:?}",
                new_awaited_action.operation_id(),
                new_awaited_action,
            ));
        };

        self.insert_sort_map_for_stage(&new_awaited_action.state().stage, &sorted_awaited_action)
            .err_tip(|| "In AwaitedActionDb::update_awaited_action")?;
        Ok(())
    }
}

/// The database for storing the state of all actions.
#[derive(MetricsComponent)]
pub struct AwaitedActionDbImpl<I: InstantWrapper, NowFn: Fn() -> I> {
    /// A lookup table to lookup the state of an action by its client operation id.
    #[metric(group = "client_operation_ids")]
    client_operation_to_awaited_action: EvictingMap<OperationId, Arc<ClientAwaitedAction>, I>,

    /// A lookup table to lookup the state of an action by its worker operation id.
    #[metric(group = "operation_ids")]
    operation_id_to_awaited_action: BTreeMap<OperationId, watch::Sender<AwaitedAction>>,

    /// A lookup table to lookup the state of an action by its unique qualifier.
    #[metric(group = "action_info_hash_key_to_awaited_action")]
    action_info_hash_key_to_awaited_action: HashMap<ActionUniqueKey, OperationId>,

    /// A sorted set of [`AwaitedAction`]s. A wrapper is used to perform sorting
    /// based on the [`AwaitedActionSortKey`] of the [`AwaitedAction`].
    ///
    /// See [`AwaitedActionSortKey`] for more information on the ordering.
    #[metric(group = "sorted_action_infos")]
    sorted_action_info_hash_keys: SortedAwaitedActions,

    /// The number of connected clients for each operation id.
    #[metric(group = "connected_clients_for_operation_id")]
    connected_clients_for_operation_id: HashMap<OperationId, usize>,

    /// Where to send notifications about important events related to actions.
    action_event_tx: mpsc::UnboundedSender<ActionEvent>,

    /// The function to get the current time.
    now_fn: NowFn,
}

impl<I: InstantWrapper, NowFn: Fn() -> I + Clone + Send + Sync> AwaitedActionDbImpl<I, NowFn> {
    async fn get_awaited_action_by_id(
        &self,
        client_operation_id: &OperationId,
    ) -> Result<Option<MemoryAwaitedActionSubscriber<I, NowFn>>, Error> {
        let maybe_client_awaited_action = self
            .client_operation_to_awaited_action
            .get(client_operation_id)
            .await;
        let Some(client_awaited_action) = maybe_client_awaited_action else {
            return Ok(None);
        };

        self.operation_id_to_awaited_action
            .get(client_awaited_action.operation_id())
            .map(|tx| {
                Some(MemoryAwaitedActionSubscriber::new_with_client(
                    tx.subscribe(),
                    client_operation_id.clone(),
                    self.action_event_tx.clone(),
                    self.now_fn.clone(),
                ))
            })
            .ok_or_else(|| {
                make_err!(
                    Code::Internal,
                    "Failed to get client operation id {client_operation_id:?}"
                )
            })
    }

    /// Processes action events that need to be handled by the database.
    async fn handle_action_events(
        &mut self,
        action_events: impl IntoIterator<Item = ActionEvent>,
    ) -> NoEarlyReturn {
        for action in action_events {
            event!(Level::DEBUG, ?action, "Handling action");
            match action {
                ActionEvent::ClientDroppedOperation(operation_id) => {
                    // Cleanup operation_id_to_awaited_action.
                    let Some(tx) = self.operation_id_to_awaited_action.remove(&operation_id) else {
                        event!(
                            Level::ERROR,
                            ?operation_id,
                            "operation_id_to_awaited_action does not have operation_id"
                        );
                        continue;
                    };
                    let connected_clients = if let Some(connected_clients) = self
                        .connected_clients_for_operation_id
                        .remove(&operation_id)
                    {
                        connected_clients - 1
                    } else {
                        event!(
                            Level::ERROR,
                            ?operation_id,
                            "connected_clients_for_operation_id does not have operation_id"
                        );
                        0
                    };
                    // Note: It is rare to have more than one client listening
                    // to the same action, so we assume that we are the last
                    // client and insert it back into the map if we detect that
                    // there are still clients listening (ie: the happy path
                    // is operation.connected_clients == 0).
                    if connected_clients != 0 {
                        self.operation_id_to_awaited_action
                            .insert(operation_id.clone(), tx);
                        self.connected_clients_for_operation_id
                            .insert(operation_id, connected_clients);
                        continue;
                    }
                    event!(
                        Level::DEBUG,
                        ?operation_id,
                        "Clearing operation from state manager"
                    );
                    let awaited_action = tx.borrow().clone();
                    // Cleanup action_info_hash_key_to_awaited_action if it was marked cached.
                    match &awaited_action.action_info().unique_qualifier {
                        ActionUniqueQualifier::Cachable(action_key) => {
                            let maybe_awaited_action = self
                                .action_info_hash_key_to_awaited_action
                                .remove(action_key);
                            if !awaited_action.state().stage.is_finished()
                                && maybe_awaited_action.is_none()
                            {
                                event!(
                                    Level::ERROR,
                                    ?operation_id,
                                    ?awaited_action,
                                    ?action_key,
                                    "action_info_hash_key_to_awaited_action and operation_id_to_awaited_action are out of sync",
                                );
                            }
                        }
                        ActionUniqueQualifier::Uncachable(_action_key) => {
                            // This Operation should not be in the hash_key map.
                        }
                    }

                    // Cleanup sorted_awaited_action.
                    let sort_key = awaited_action.sort_key();
                    let sort_btree_for_state = self
                        .sorted_action_info_hash_keys
                        .btree_for_state(&awaited_action.state().stage);

                    let maybe_sorted_awaited_action =
                        sort_btree_for_state.take(&SortedAwaitedAction {
                            sort_key,
                            operation_id: operation_id.clone(),
                        });
                    if maybe_sorted_awaited_action.is_none() {
                        event!(
                            Level::ERROR,
                            ?operation_id,
                            ?sort_key,
                            "Expected maybe_sorted_awaited_action to have {sort_key:?}",
                        );
                    }
                }
                ActionEvent::ClientKeepAlive(client_id) => {
                    let maybe_size = self
                        .client_operation_to_awaited_action
                        .size_for_key(&client_id)
                        .await;
                    if maybe_size.is_none() {
                        event!(
                            Level::ERROR,
                            ?client_id,
                            "client_operation_to_awaited_action does not have client_id",
                        );
                    }
                }
            }
        }
        NoEarlyReturn
    }

    fn get_awaited_actions_range(
        &self,
        start: Bound<&OperationId>,
        end: Bound<&OperationId>,
    ) -> impl Iterator<Item = (&'_ OperationId, MemoryAwaitedActionSubscriber<I, NowFn>)> {
        self.operation_id_to_awaited_action
            .range((start, end))
            .map(|(operation_id, tx)| {
                (
                    operation_id,
                    MemoryAwaitedActionSubscriber::<I, NowFn>::new(tx.subscribe()),
                )
            })
    }

    fn get_by_operation_id(
        &self,
        operation_id: &OperationId,
    ) -> Option<MemoryAwaitedActionSubscriber<I, NowFn>> {
        self.operation_id_to_awaited_action
            .get(operation_id)
            .map(|tx| MemoryAwaitedActionSubscriber::<I, NowFn>::new(tx.subscribe()))
    }

    fn get_range_of_actions<'a, 'b>(
        &'a self,
        state: SortedAwaitedActionState,
        range: impl RangeBounds<SortedAwaitedAction> + 'b,
    ) -> impl DoubleEndedIterator<
        Item = Result<
            (
                &'a SortedAwaitedAction,
                MemoryAwaitedActionSubscriber<I, NowFn>,
            ),
            Error,
        >,
    > + 'a {
        let btree = match state {
            SortedAwaitedActionState::CacheCheck => &self.sorted_action_info_hash_keys.cache_check,
            SortedAwaitedActionState::Queued => &self.sorted_action_info_hash_keys.queued,
            SortedAwaitedActionState::Executing => &self.sorted_action_info_hash_keys.executing,
            SortedAwaitedActionState::Completed => &self.sorted_action_info_hash_keys.completed,
        };
        btree.range(range).map(|sorted_awaited_action| {
            let operation_id = &sorted_awaited_action.operation_id;
            self.get_by_operation_id(operation_id)
                .ok_or_else(|| {
                    make_err!(
                        Code::Internal,
                        "Failed to get operation id {}",
                        operation_id
                    )
                })
                .map(|subscriber| (sorted_awaited_action, subscriber))
        })
    }

    fn process_state_changes_for_hash_key_map(
        action_info_hash_key_to_awaited_action: &mut HashMap<ActionUniqueKey, OperationId>,
        new_awaited_action: &AwaitedAction,
    ) {
        // Only process changes if the stage is not finished.
        if !new_awaited_action.state().stage.is_finished() {
            return;
        }
        match &new_awaited_action.action_info().unique_qualifier {
            ActionUniqueQualifier::Cachable(action_key) => {
                let maybe_awaited_action =
                    action_info_hash_key_to_awaited_action.remove(action_key);
                match maybe_awaited_action {
                    Some(removed_operation_id) => {
                        if &removed_operation_id != new_awaited_action.operation_id() {
                            event!(
                                Level::ERROR,
                                ?removed_operation_id,
                                ?new_awaited_action,
                                ?action_key,
                                "action_info_hash_key_to_awaited_action and operation_id_to_awaited_action are out of sync",
                            );
                        }
                    }
                    None => {
                        event!(
                            Level::ERROR,
                            ?new_awaited_action,
                            ?action_key,
                            "action_info_hash_key_to_awaited_action out of sync, it should have had the unique_key",
                        );
                    }
                }
            }
            ActionUniqueQualifier::Uncachable(_action_key) => {
                // If we are not cachable, the action should not be in the
                // hash_key map, so we don't need to process anything in
                // action_info_hash_key_to_awaited_action.
            }
        }
    }

    fn update_awaited_action(
        &mut self,
        mut new_awaited_action: AwaitedAction,
    ) -> Result<(), Error> {
        let tx = self
            .operation_id_to_awaited_action
            .get(new_awaited_action.operation_id())
            .ok_or_else(|| {
                make_err!(
                    Code::Internal,
                    "OperationId does not exist in map in AwaitedActionDb::update_awaited_action"
                )
            })?;
        {
            // Note: It's important to drop old_awaited_action before we call
            // send_replace or we will have a deadlock.
            let old_awaited_action = tx.borrow();

            // Do not process changes if the action version is not in sync with
            // what the sender based the update on.
            if old_awaited_action.version() != new_awaited_action.version() {
                return Err(make_err!(
                    // From: https://grpc.github.io/grpc/core/md_doc_statuscodes.html
                    // Use ABORTED if the client should retry at a higher level
                    // (e.g., when a client-specified test-and-set fails,
                    // indicating the client should restart a read-modify-write
                    // sequence)
                    Code::Aborted,
                    "{} Expected {} but got {} for operation_id {:?} - {:?}",
                    "Tried to update an awaited action with an incorrect version.",
                    old_awaited_action.version(),
                    new_awaited_action.version(),
                    old_awaited_action,
                    new_awaited_action,
                ));
            }
            new_awaited_action.increment_version();

            error_if!(
                old_awaited_action.action_info().unique_qualifier
                    != new_awaited_action.action_info().unique_qualifier,
                "Unique key changed for operation_id {:?} - {:?} - {:?}",
                new_awaited_action.operation_id(),
                old_awaited_action.action_info(),
                new_awaited_action.action_info(),
            );
            let is_same_stage = old_awaited_action
                .state()
                .stage
                .is_same_stage(&new_awaited_action.state().stage);

            if !is_same_stage {
                self.sorted_action_info_hash_keys
                    .process_state_changes(&old_awaited_action, &new_awaited_action)?;
                Self::process_state_changes_for_hash_key_map(
                    &mut self.action_info_hash_key_to_awaited_action,
                    &new_awaited_action,
                );
            }
        }

        // Notify all listeners of the new state and ignore if no one is listening.
        // Note: Do not use `.send()` as it will not update the state if all listeners
        // are dropped.
        let _ = tx.send_replace(new_awaited_action);

        Ok(())
    }

    /// Creates a new [`ClientAwaitedAction`] and a [`watch::Receiver`] to
    /// listen for changes. We don't do this in-line because it is important
    /// to ALWAYS construct a [`ClientAwaitedAction`] before inserting it into
    /// the map. Failing to do so may result in memory leaks. This is because
    /// [`ClientAwaitedAction`] implements a drop function that will trigger
    /// cleanup of the other maps on drop.
    fn make_client_awaited_action(
        &mut self,
        operation_id: &OperationId,
        awaited_action: AwaitedAction,
    ) -> (Arc<ClientAwaitedAction>, watch::Receiver<AwaitedAction>) {
        let (tx, rx) = watch::channel(awaited_action);
        let client_awaited_action = Arc::new(ClientAwaitedAction::new(
            operation_id.clone(),
            self.action_event_tx.clone(),
        ));
        self.operation_id_to_awaited_action
            .insert(operation_id.clone(), tx);
        self.connected_clients_for_operation_id
            .insert(operation_id.clone(), 1);
        (client_awaited_action, rx)
    }

    async fn add_action(
        &mut self,
        client_operation_id: OperationId,
        action_info: Arc<ActionInfo>,
    ) -> Result<MemoryAwaitedActionSubscriber<I, NowFn>, Error> {
        // Check to see if the action is already known and subscribe if it is.
        let subscription_result = self
            .try_subscribe(
                &client_operation_id,
                &action_info.unique_qualifier,
                action_info.priority,
            )
            .await
            .err_tip(|| "In AwaitedActionDb::subscribe_or_add_action");
        match subscription_result {
            Err(err) => return Err(err),
            Ok(Some(subscription)) => return Ok(subscription),
            Ok(None) => { /* Add item to queue. */ }
        }

        let maybe_unique_key = match &action_info.unique_qualifier {
            ActionUniqueQualifier::Cachable(unique_key) => Some(unique_key.clone()),
            ActionUniqueQualifier::Uncachable(_unique_key) => None,
        };
        let operation_id = OperationId::default();
        let awaited_action =
            AwaitedAction::new(operation_id.clone(), action_info, (self.now_fn)().now());
        debug_assert!(
            ActionStage::Queued == awaited_action.state().stage,
            "Expected action to be queued"
        );
        let sort_key = awaited_action.sort_key();

        let (client_awaited_action, rx) =
            self.make_client_awaited_action(&operation_id.clone(), awaited_action);

        event!(
            Level::DEBUG,
            ?client_operation_id,
            ?operation_id,
            ?client_awaited_action,
            "Adding action"
        );

        self.client_operation_to_awaited_action
            .insert(client_operation_id.clone(), client_awaited_action)
            .await;

        // Note: We only put items in the map that are cachable.
        if let Some(unique_key) = maybe_unique_key {
            let old_value = self
                .action_info_hash_key_to_awaited_action
                .insert(unique_key, operation_id.clone());
            if let Some(old_value) = old_value {
                event!(
                    Level::ERROR,
                    ?operation_id,
                    ?old_value,
                    "action_info_hash_key_to_awaited_action already has unique_key"
                );
            }
        }

        self.sorted_action_info_hash_keys
            .insert_sort_map_for_stage(
                &ActionStage::Queued,
                &SortedAwaitedAction {
                    sort_key,
                    operation_id,
                },
            )
            .err_tip(|| "In AwaitedActionDb::subscribe_or_add_action")?;

        Ok(MemoryAwaitedActionSubscriber::new_with_client(
            rx,
            client_operation_id,
            self.action_event_tx.clone(),
            self.now_fn.clone(),
        ))
    }

    async fn try_subscribe(
        &mut self,
        client_operation_id: &OperationId,
        unique_qualifier: &ActionUniqueQualifier,
        // TODO(allada) To simplify the scheduler 2024 refactor, we
        // removed the ability to upgrade priorities of actions.
        // we should add priority upgrades back in.
        _priority: i32,
    ) -> Result<Option<MemoryAwaitedActionSubscriber<I, NowFn>>, Error> {
        let unique_key = match unique_qualifier {
            ActionUniqueQualifier::Cachable(unique_key) => unique_key,
            ActionUniqueQualifier::Uncachable(_unique_key) => return Ok(None),
        };

        let Some(operation_id) = self.action_info_hash_key_to_awaited_action.get(unique_key) else {
            return Ok(None); // Not currently running.
        };

        let Some(tx) = self.operation_id_to_awaited_action.get(operation_id) else {
            return Err(make_err!(
                Code::Internal,
                "operation_id_to_awaited_action and action_info_hash_key_to_awaited_action are out of sync for {unique_key:?} - {operation_id}"
            ));
        };

        error_if!(
            tx.borrow().state().stage.is_finished(),
            "Tried to subscribe to a completed action but it already finished. This should never happen. {:?}",
            tx.borrow()
        );

        let maybe_connected_clients = self
            .connected_clients_for_operation_id
            .get_mut(operation_id);
        let Some(connected_clients) = maybe_connected_clients else {
            return Err(make_err!(
                Code::Internal,
                "connected_clients_for_operation_id and operation_id_to_awaited_action are out of sync for {unique_key:?} - {operation_id}"
            ));
        };
        *connected_clients += 1;

        // Immediately mark the keep alive, we don't need to wake anyone
        // so we always fake that it was not actually changed.
        // Failing update the client could lead to the client connecting
        // then not updating the keep alive in time, resulting in the
        // operation timing out due to async behavior.
        tx.send_if_modified(|awaited_action| {
            awaited_action.update_client_keep_alive((self.now_fn)().now());
            false
        });
        let subscription = tx.subscribe();

        self.client_operation_to_awaited_action
            .insert(
                client_operation_id.clone(),
                Arc::new(ClientAwaitedAction::new(
                    operation_id.clone(),
                    self.action_event_tx.clone(),
                )),
            )
            .await;

        Ok(Some(MemoryAwaitedActionSubscriber::new_with_client(
            subscription,
            client_operation_id.clone(),
            self.action_event_tx.clone(),
            self.now_fn.clone(),
        )))
    }
}

#[derive(MetricsComponent)]
pub struct MemoryAwaitedActionDb<I: InstantWrapper, NowFn: Fn() -> I> {
    #[metric]
    inner: Arc<Mutex<AwaitedActionDbImpl<I, NowFn>>>,
    tasks_change_notify: Arc<Notify>,
    _handle_awaited_action_events: JoinHandleDropGuard<()>,
}

impl<I: InstantWrapper, NowFn: Fn() -> I + Clone + Send + Sync + 'static>
    MemoryAwaitedActionDb<I, NowFn>
{
    pub fn new(
        eviction_config: &EvictionPolicy,
        tasks_change_notify: Arc<Notify>,
        now_fn: NowFn,
    ) -> Self {
        let (action_event_tx, mut action_event_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Mutex::new(AwaitedActionDbImpl {
            client_operation_to_awaited_action: EvictingMap::new(eviction_config, (now_fn)()),
            operation_id_to_awaited_action: BTreeMap::new(),
            action_info_hash_key_to_awaited_action: HashMap::new(),
            sorted_action_info_hash_keys: SortedAwaitedActions::default(),
            connected_clients_for_operation_id: HashMap::new(),
            action_event_tx,
            now_fn,
        }));
        let weak_inner = Arc::downgrade(&inner);
        Self {
            inner,
            tasks_change_notify,
            _handle_awaited_action_events: spawn!("handle_awaited_action_events", async move {
                let mut dropped_operation_ids = Vec::with_capacity(MAX_ACTION_EVENTS_RX_PER_CYCLE);
                loop {
                    dropped_operation_ids.clear();
                    action_event_rx
                        .recv_many(&mut dropped_operation_ids, MAX_ACTION_EVENTS_RX_PER_CYCLE)
                        .await;
                    let Some(inner) = weak_inner.upgrade() else {
                        return; // Nothing to cleanup, our struct is dropped.
                    };
                    let mut inner = inner.lock().await;
                    inner
                        .handle_action_events(dropped_operation_ids.drain(..))
                        .await;
                }
            }),
        }
    }
}

impl<I: InstantWrapper, NowFn: Fn() -> I + Clone + Send + Sync + 'static> AwaitedActionDb
    for MemoryAwaitedActionDb<I, NowFn>
{
    type Subscriber = MemoryAwaitedActionSubscriber<I, NowFn>;

    async fn get_awaited_action_by_id(
        &self,
        client_operation_id: &OperationId,
    ) -> Result<Option<Self::Subscriber>, Error> {
        self.inner
            .lock()
            .await
            .get_awaited_action_by_id(client_operation_id)
            .await
    }

    async fn get_all_awaited_actions(
        &self,
    ) -> Result<impl Stream<Item = Result<Self::Subscriber, Error>>, Error> {
        Ok(ChunkedStream::new(
            Bound::Unbounded,
            Bound::Unbounded,
            move |start, end, mut output| async move {
                let inner = self.inner.lock().await;
                let mut maybe_new_start = None;

                for (operation_id, item) in
                    inner.get_awaited_actions_range(start.as_ref(), end.as_ref())
                {
                    output.push_back(item);
                    maybe_new_start = Some(operation_id);
                }

                Ok(maybe_new_start
                    .map(|new_start| ((Bound::Excluded(new_start.clone()), end), output)))
            },
        ))
    }

    async fn get_by_operation_id(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<Self::Subscriber>, Error> {
        Ok(self.inner.lock().await.get_by_operation_id(operation_id))
    }

    async fn get_range_of_actions(
        &self,
        state: SortedAwaitedActionState,
        start: Bound<SortedAwaitedAction>,
        end: Bound<SortedAwaitedAction>,
        desc: bool,
    ) -> Result<impl Stream<Item = Result<Self::Subscriber, Error>> + Send, Error> {
        Ok(ChunkedStream::new(
            start,
            end,
            move |start, end, mut output| async move {
                let inner = self.inner.lock().await;
                let mut done = true;
                let mut new_start = start.as_ref();
                let mut new_end = end.as_ref();

                let iterator = inner
                    .get_range_of_actions(state, (start.as_ref(), end.as_ref()))
                    .map(|res| res.err_tip(|| "In AwaitedActionDb::get_range_of_actions"));

                // TODO(allada) This should probably use the `.left()/right()` pattern,
                // but that doesn't exist in the std or any libraries we use.
                if desc {
                    for result in iterator.rev() {
                        let (sorted_awaited_action, item) =
                            result.err_tip(|| "In AwaitedActionDb::get_range_of_actions")?;
                        output.push_back(item);
                        new_end = Bound::Excluded(sorted_awaited_action);
                        done = false;
                    }
                } else {
                    for result in iterator {
                        let (sorted_awaited_action, item) =
                            result.err_tip(|| "In AwaitedActionDb::get_range_of_actions")?;
                        output.push_back(item);
                        new_start = Bound::Excluded(sorted_awaited_action);
                        done = false;
                    }
                }
                if done {
                    return Ok(None);
                }
                Ok(Some(((new_start.cloned(), new_end.cloned()), output)))
            },
        ))
    }

    async fn update_awaited_action(&self, new_awaited_action: AwaitedAction) -> Result<(), Error> {
        self.inner
            .lock()
            .await
            .update_awaited_action(new_awaited_action)?;
        self.tasks_change_notify.notify_one();
        Ok(())
    }

    async fn add_action(
        &self,
        client_operation_id: OperationId,
        action_info: Arc<ActionInfo>,
    ) -> Result<Self::Subscriber, Error> {
        let subscriber = self
            .inner
            .lock()
            .await
            .add_action(client_operation_id, action_info)
            .await?;
        self.tasks_change_notify.notify_one();
        Ok(subscriber)
    }
}
