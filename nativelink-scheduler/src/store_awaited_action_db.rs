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
use std::ops::Bound;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use nativelink_error::{make_err, make_input_err, Code, Error, ResultExt};
use nativelink_metric::MetricsComponent;
use nativelink_util::action_messages::{
    ActionInfo, ActionStage, ActionUniqueQualifier, OperationId,
};
use nativelink_util::instant_wrapper::InstantWrapper;
use nativelink_util::spawn;
use nativelink_util::store_trait::{
    FalseValue, SchedulerCurrentVersionProvider, SchedulerIndexProvider, SchedulerStore,
    SchedulerStoreDataProvider, SchedulerStoreDecodeTo, SchedulerStoreKeyProvider,
    SchedulerSubscription, SchedulerSubscriptionManager, StoreKey, TrueValue,
};
use nativelink_util::task::JoinHandleDropGuard;
use tokio::sync::Notify;
use tracing::{event, Level};

use crate::awaited_action_db::{
    AwaitedAction, AwaitedActionDb, AwaitedActionSubscriber, SortedAwaitedAction,
    SortedAwaitedActionState,
};

type ClientOperationId = OperationId;

/// Duration to wait before sending client keep alive messages.
const CLIENT_KEEPALIVE_DURATION: Duration = Duration::from_secs(10);

/// Maximum number of retries to update client keep alive.
const MAX_RETRIES_FOR_CLIENT_KEEPALIVE: u32 = 8;

enum OperationSubscriberState<Sub> {
    Unsubscribed,
    Subscribed(Sub),
}

pub struct OperationSubscriber<S: SchedulerStore, I: InstantWrapper, NowFn: Fn() -> I> {
    maybe_client_operation_id: Option<ClientOperationId>,
    subscription_key: OperationIdToAwaitedAction<'static>,
    weak_store: Weak<S>,
    state: OperationSubscriberState<
        <S::SubscriptionManager as SchedulerSubscriptionManager>::Subscription,
    >,
    last_known_keepalive_ts: AtomicU64,
    now_fn: NowFn,
}
impl<S, I, NowFn> OperationSubscriber<S, I, NowFn>
where
    S: SchedulerStore,
    I: InstantWrapper,
    NowFn: Fn() -> I,
{
    const fn new(
        maybe_client_operation_id: Option<ClientOperationId>,
        subscription_key: OperationIdToAwaitedAction<'static>,
        weak_store: Weak<S>,
        now_fn: NowFn,
    ) -> Self {
        Self {
            maybe_client_operation_id,
            subscription_key,
            weak_store,
            last_known_keepalive_ts: AtomicU64::new(0),
            state: OperationSubscriberState::Unsubscribed,
            now_fn,
        }
    }

    async fn inner_get_awaited_action(
        store: &S,
        key: OperationIdToAwaitedAction<'_>,
        maybe_client_operation_id: Option<ClientOperationId>,
        last_known_keepalive_ts: &AtomicU64,
    ) -> Result<AwaitedAction, Error> {
        let mut awaited_action = store
            .get_and_decode(key.borrow())
            .await
            .err_tip(|| format!("In OperationSubscriber::get_awaited_action {key:?}"))?
            .ok_or_else(|| {
                make_err!(
                    Code::NotFound,
                    "Could not find AwaitedAction for the given operation id {key:?}",
                )
            })?;
        if let Some(client_operation_id) = maybe_client_operation_id {
            awaited_action.set_client_operation_id(client_operation_id);
        }
        last_known_keepalive_ts.store(
            awaited_action
                .last_client_keepalive_timestamp()
                .unix_timestamp(),
            Ordering::Release,
        );
        Ok(awaited_action)
    }

    async fn get_awaited_action(&self) -> Result<AwaitedAction, Error> {
        let store = self
            .weak_store
            .upgrade()
            .err_tip(|| "Store gone in OperationSubscriber::get_awaited_action")?;
        Self::inner_get_awaited_action(
            store.as_ref(),
            self.subscription_key.borrow(),
            self.maybe_client_operation_id.clone(),
            &self.last_known_keepalive_ts,
        )
        .await
    }
}

impl<S, I, NowFn> AwaitedActionSubscriber for OperationSubscriber<S, I, NowFn>
where
    S: SchedulerStore,
    I: InstantWrapper,
    NowFn: Fn() -> I + Send + Sync + 'static,
{
    async fn changed(&mut self) -> Result<AwaitedAction, Error> {
        let store = self
            .weak_store
            .upgrade()
            .err_tip(|| "Store gone in OperationSubscriber::get_awaited_action")?;
        let subscription = match &mut self.state {
            OperationSubscriberState::Unsubscribed => {
                let subscription = store
                    .subscription_manager()
                    .err_tip(|| "In OperationSubscriber::changed::subscription_manager")?
                    .subscribe(self.subscription_key.borrow())
                    .err_tip(|| "In OperationSubscriber::changed::subscribe")?;
                self.state = OperationSubscriberState::Subscribed(subscription);
                let OperationSubscriberState::Subscribed(subscription) = &mut self.state else {
                    unreachable!("Subscription should be in Subscribed state");
                };
                subscription
            }
            OperationSubscriberState::Subscribed(subscription) => subscription,
        };

        let changed_fut = subscription.changed();
        tokio::pin!(changed_fut);
        loop {
            let mut retries = 0;
            loop {
                let last_known_keepalive_ts = self.last_known_keepalive_ts.load(Ordering::Acquire);
                if I::from_secs(last_known_keepalive_ts).elapsed() <= CLIENT_KEEPALIVE_DURATION {
                    break; // We are still within the keep alive duration.
                }
                if retries > MAX_RETRIES_FOR_CLIENT_KEEPALIVE {
                    return Err(make_err!(
                        Code::Aborted,
                        "Could not update client keep alive for AwaitedAction",
                    ));
                }
                let mut awaited_action = Self::inner_get_awaited_action(
                    store.as_ref(),
                    self.subscription_key.borrow(),
                    self.maybe_client_operation_id.clone(),
                    &self.last_known_keepalive_ts,
                )
                .await
                .err_tip(|| "In OperationSubscriber::changed")?;
                awaited_action.update_client_keep_alive((self.now_fn)().now());
                let update_res = inner_update_awaited_action(store.as_ref(), awaited_action)
                    .await
                    .err_tip(|| "In OperationSubscriber::changed");
                if update_res.is_ok() {
                    break;
                }
                retries += 1;
                // Wait a tick before retrying.
                (self.now_fn)().sleep(Duration::from_millis(100)).await;
            }
            let sleep_fut = (self.now_fn)().sleep(CLIENT_KEEPALIVE_DURATION);
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

        Self::inner_get_awaited_action(
            store.as_ref(),
            self.subscription_key.borrow(),
            self.maybe_client_operation_id.clone(),
            &self.last_known_keepalive_ts,
        )
        .await
        .err_tip(|| "In OperationSubscriber::changed")
    }

    async fn borrow(&self) -> Result<AwaitedAction, Error> {
        self.get_awaited_action()
            .await
            .err_tip(|| "In OperationSubscriber::borrow")
    }
}

fn awaited_action_decode(version: u64, data: &Bytes) -> Result<AwaitedAction, Error> {
    let mut awaited_action: AwaitedAction = serde_json::from_slice(data)
        .map_err(|e| make_input_err!("In AwaitedAction::decode - {e:?}"))?;
    awaited_action.set_version(version);
    Ok(awaited_action)
}

const OPERATION_ID_TO_AWAITED_ACTION_KEY_PREFIX: &str = "aa_";
const CLIENT_ID_TO_OPERATION_ID_KEY_PREFIX: &str = "cid_";

#[derive(Debug)]
struct OperationIdToAwaitedAction<'a>(Cow<'a, OperationId>);
impl OperationIdToAwaitedAction<'_> {
    fn borrow(&self) -> OperationIdToAwaitedAction<'_> {
        OperationIdToAwaitedAction(Cow::Borrowed(self.0.as_ref()))
    }
}
impl SchedulerStoreKeyProvider for OperationIdToAwaitedAction<'_> {
    type Versioned = TrueValue;
    fn get_key(&self) -> StoreKey<'static> {
        StoreKey::Str(Cow::Owned(format!(
            "{OPERATION_ID_TO_AWAITED_ACTION_KEY_PREFIX}{}",
            self.0
        )))
    }
}
impl SchedulerStoreDecodeTo for OperationIdToAwaitedAction<'_> {
    type DecodeOutput = AwaitedAction;
    fn decode(version: u64, data: Bytes) -> Result<Self::DecodeOutput, Error> {
        awaited_action_decode(version, &data)
    }
}

struct ClientIdToOperationId<'a>(&'a OperationId);
impl SchedulerStoreKeyProvider for ClientIdToOperationId<'_> {
    type Versioned = FalseValue;
    fn get_key(&self) -> StoreKey<'static> {
        StoreKey::Str(Cow::Owned(format!(
            "{CLIENT_ID_TO_OPERATION_ID_KEY_PREFIX}{}",
            self.0
        )))
    }
}
impl SchedulerStoreDecodeTo for ClientIdToOperationId<'_> {
    type DecodeOutput = OperationId;
    fn decode(_version: u64, data: Bytes) -> Result<Self::DecodeOutput, Error> {
        OperationId::try_from(data).err_tip(|| "In ClientIdToOperationId::decode")
    }
}

// TODO(allada) We only need operation_id here, it would be nice if we had a way
// to tell the decoder we only care about specific fields.
struct SearchUniqueQualifierToAwaitedAction<'a>(&'a ActionUniqueQualifier);
impl SchedulerIndexProvider for SearchUniqueQualifierToAwaitedAction<'_> {
    const KEY_PREFIX: &'static str = OPERATION_ID_TO_AWAITED_ACTION_KEY_PREFIX;
    const INDEX_NAME: &'static str = "unique_qualifier";
    type Versioned = TrueValue;
    fn index_value(&self) -> Cow<'_, str> {
        Cow::Owned(format!("{}", self.0))
    }
}
impl SchedulerStoreDecodeTo for SearchUniqueQualifierToAwaitedAction<'_> {
    type DecodeOutput = AwaitedAction;
    fn decode(version: u64, data: Bytes) -> Result<Self::DecodeOutput, Error> {
        awaited_action_decode(version, &data)
    }
}

struct SearchStateToAwaitedAction(&'static str);
impl SchedulerIndexProvider for SearchStateToAwaitedAction {
    const KEY_PREFIX: &'static str = OPERATION_ID_TO_AWAITED_ACTION_KEY_PREFIX;
    const INDEX_NAME: &'static str = "state";
    const MAYBE_SORT_KEY: Option<&'static str> = Some("sort_key");
    type Versioned = TrueValue;
    fn index_value(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.0)
    }
}
impl SchedulerStoreDecodeTo for SearchStateToAwaitedAction {
    type DecodeOutput = AwaitedAction;
    fn decode(version: u64, data: Bytes) -> Result<Self::DecodeOutput, Error> {
        awaited_action_decode(version, &data)
    }
}

const fn get_state_prefix(state: SortedAwaitedActionState) -> &'static str {
    match state {
        SortedAwaitedActionState::CacheCheck => "cache_check",
        SortedAwaitedActionState::Queued => "queued",
        SortedAwaitedActionState::Executing => "executing",
        SortedAwaitedActionState::Completed => "completed",
    }
}

struct UpdateOperationIdToAwaitedAction(AwaitedAction);
impl SchedulerCurrentVersionProvider for UpdateOperationIdToAwaitedAction {
    fn current_version(&self) -> u64 {
        self.0.version()
    }
}
impl SchedulerStoreKeyProvider for UpdateOperationIdToAwaitedAction {
    type Versioned = TrueValue;
    fn get_key(&self) -> StoreKey<'static> {
        OperationIdToAwaitedAction(Cow::Borrowed(self.0.operation_id())).get_key()
    }
}
impl SchedulerStoreDataProvider for UpdateOperationIdToAwaitedAction {
    fn try_into_bytes(self) -> Result<Bytes, Error> {
        serde_json::to_string(&self.0)
            .map(Bytes::from)
            .map_err(|e| make_input_err!("Could not convert AwaitedAction to json - {e:?}"))
    }
    fn get_indexes(&self) -> Result<Vec<(&'static str, Bytes)>, Error> {
        let unique_qualifier = &self.0.action_info().unique_qualifier;
        let maybe_unique_qualifier = match &unique_qualifier {
            ActionUniqueQualifier::Cachable(_) => Some(unique_qualifier),
            ActionUniqueQualifier::Uncachable(_) => None,
        };
        let mut output = Vec::with_capacity(1 + maybe_unique_qualifier.map_or(0, |_| 1));
        if maybe_unique_qualifier.is_some() {
            output.push((
                "unique_qualifier",
                Bytes::from(unique_qualifier.to_string()),
            ));
        }
        {
            let state = SortedAwaitedActionState::try_from(&self.0.state().stage)
                .err_tip(|| "In UpdateOperationIdToAwaitedAction::get_index")?;
            output.push(("state", Bytes::from(get_state_prefix(state))));
            let sorted_awaited_action = SortedAwaitedAction::from(&self.0);
            output.push((
                "sort_key",
                // We encode to hex to ensure that the sort key is lexicographically sorted.
                Bytes::from(format!("{:016x}", sorted_awaited_action.sort_key.as_u64())),
            ));
        }
        Ok(output)
    }
}

struct UpdateClientIdToOperationId {
    client_operation_id: ClientOperationId,
    operation_id: OperationId,
}
impl SchedulerStoreKeyProvider for UpdateClientIdToOperationId {
    type Versioned = FalseValue;
    fn get_key(&self) -> StoreKey<'static> {
        ClientIdToOperationId(&self.client_operation_id).get_key()
    }
}
impl SchedulerStoreDataProvider for UpdateClientIdToOperationId {
    fn try_into_bytes(self) -> Result<Bytes, Error> {
        serde_json::to_string(&self.operation_id)
            .map(Bytes::from)
            .map_err(|e| make_input_err!("Could not convert OperationId to json - {e:?}"))
    }
}

async fn inner_update_awaited_action(
    store: &impl SchedulerStore,
    mut new_awaited_action: AwaitedAction,
) -> Result<(), Error> {
    let operation_id = new_awaited_action.operation_id().clone();
    if new_awaited_action.state().client_operation_id != operation_id {
        // Just in case the client_operation_id was set to something else
        // we put it back to the underlying operation_id.
        new_awaited_action.set_client_operation_id(operation_id.clone());
    }
    let maybe_version = store
        .update_data(UpdateOperationIdToAwaitedAction(new_awaited_action))
        .await
        .err_tip(|| "In RedisAwaitedActionDb::update_awaited_action")?;
    if maybe_version.is_none() {
        return Err(make_err!(
            Code::Aborted,
            "Could not update AwaitedAction because the version did not match for {operation_id:?}",
        ));
    }
    Ok(())
}

#[derive(MetricsComponent)]
pub struct StoreAwaitedActionDb<S, F, I, NowFn>
where
    S: SchedulerStore,
    F: Fn() -> OperationId,
    I: InstantWrapper,
    NowFn: Fn() -> I,
{
    store: Arc<S>,
    now_fn: NowFn,
    operation_id_creator: F,
    _pull_task_change_subscriber_spawn: JoinHandleDropGuard<()>,
}

impl<S, F, I, NowFn> StoreAwaitedActionDb<S, F, I, NowFn>
where
    S: SchedulerStore,
    F: Fn() -> OperationId,
    I: InstantWrapper,
    NowFn: Fn() -> I + Send + Sync + Clone + 'static,
{
    pub fn new(
        store: Arc<S>,
        task_change_publisher: Arc<Notify>,
        now_fn: NowFn,
        operation_id_creator: F,
    ) -> Result<Self, Error> {
        let mut subscription = store
            .subscription_manager()
            .err_tip(|| "In RedisAwaitedActionDb::new")?
            .subscribe(OperationIdToAwaitedAction(Cow::Owned(OperationId::String(
                String::new(),
            ))))
            .err_tip(|| "In RedisAwaitedActionDb::new")?;
        let pull_task_change_subscriber = spawn!(
            "redis_awaited_action_db_pull_task_change_subscriber",
            async move {
                loop {
                    let changed_res = subscription
                        .changed()
                        .await
                        .err_tip(|| "In RedisAwaitedActionDb::new");
                    if let Err(err) = changed_res {
                        event!(
                            Level::ERROR,
                            "Error waiting for pull task change subscriber in RedisAwaitedActionDb::new  - {err:?}"
                        );
                        // Sleep for a second to avoid a busy loop, then trigger the notify
                        // so if a reconnect happens we let local resources know that things
                        // might have changed.
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    task_change_publisher.as_ref().notify_one();
                }
            }
        );
        Ok(Self {
            store,
            now_fn,
            operation_id_creator,
            _pull_task_change_subscriber_spawn: pull_task_change_subscriber,
        })
    }

    async fn try_subscribe(
        &self,
        client_operation_id: &ClientOperationId,
        unique_qualifier: &ActionUniqueQualifier,
        // TODO(allada) To simplify the scheduler 2024 refactor, we
        // removed the ability to upgrade priorities of actions.
        // we should add priority upgrades back in.
        _priority: i32,
    ) -> Result<Option<OperationSubscriber<S, I, NowFn>>, Error> {
        match unique_qualifier {
            ActionUniqueQualifier::Cachable(_) => {}
            ActionUniqueQualifier::Uncachable(_) => return Ok(None),
        }
        let stream = self
            .store
            .search_by_index_prefix(SearchUniqueQualifierToAwaitedAction(unique_qualifier))
            .await
            .err_tip(|| "In RedisAwaitedActionDb::try_subscribe")?;
        tokio::pin!(stream);
        let maybe_awaited_action = stream
            .try_next()
            .await
            .err_tip(|| "In RedisAwaitedActionDb::try_subscribe")?;
        match maybe_awaited_action {
            Some(mut awaited_action) => {
                // TODO(allada) We don't support joining completed jobs because we
                // need to also check that all the data is still in the cache.
                if awaited_action.state().stage.is_finished() {
                    return Ok(None);
                }
                // TODO(allada) We only care about the operation_id here, we should
                // have a way to tell the decoder we only care about specific fields.
                let operation_id = awaited_action.operation_id().clone();

                awaited_action.update_client_keep_alive((self.now_fn)().now());
                let update_res = inner_update_awaited_action(self.store.as_ref(), awaited_action)
                    .await
                    .err_tip(|| "In OperationSubscriber::changed");
                if let Err(err) = update_res {
                    event!(
                        Level::WARN,
                        "Error updating client keep alive in RedisAwaitedActionDb::try_subscribe - {err:?} - This is not a critical error, but we did decide to create a new action instead of joining an existing one."
                    );
                    return Ok(None);
                }

                Ok(Some(OperationSubscriber::new(
                    Some(client_operation_id.clone()),
                    OperationIdToAwaitedAction(Cow::Owned(operation_id)),
                    Arc::downgrade(&self.store),
                    self.now_fn.clone(),
                )))
            }
            None => Ok(None),
        }
    }

    async fn inner_get_awaited_action_by_id(
        &self,
        client_operation_id: &ClientOperationId,
    ) -> Result<Option<OperationSubscriber<S, I, NowFn>>, Error> {
        let maybe_operation_id = self
            .store
            .get_and_decode(ClientIdToOperationId(client_operation_id))
            .await
            .err_tip(|| "In RedisAwaitedActionDb::get_awaited_action_by_id")?;
        let Some(operation_id) = maybe_operation_id else {
            return Ok(None);
        };
        Ok(Some(OperationSubscriber::new(
            Some(client_operation_id.clone()),
            OperationIdToAwaitedAction(Cow::Owned(operation_id)),
            Arc::downgrade(&self.store),
            self.now_fn.clone(),
        )))
    }
}

impl<S, F, I, NowFn> AwaitedActionDb for StoreAwaitedActionDb<S, F, I, NowFn>
where
    S: SchedulerStore,
    F: Fn() -> OperationId + Send + Sync + Unpin + 'static,
    I: InstantWrapper,
    NowFn: Fn() -> I + Send + Sync + Unpin + Clone + 'static,
{
    type Subscriber = OperationSubscriber<S, I, NowFn>;

    async fn get_awaited_action_by_id(
        &self,
        client_operation_id: &ClientOperationId,
    ) -> Result<Option<Self::Subscriber>, Error> {
        self.inner_get_awaited_action_by_id(client_operation_id)
            .await
    }

    async fn get_by_operation_id(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<Self::Subscriber>, Error> {
        Ok(Some(OperationSubscriber::new(
            None,
            OperationIdToAwaitedAction(Cow::Owned(operation_id.clone())),
            Arc::downgrade(&self.store),
            self.now_fn.clone(),
        )))
    }

    async fn update_awaited_action(&self, new_awaited_action: AwaitedAction) -> Result<(), Error> {
        inner_update_awaited_action(self.store.as_ref(), new_awaited_action).await
    }

    async fn add_action(
        &self,
        client_operation_id: ClientOperationId,
        action_info: Arc<ActionInfo>,
    ) -> Result<Self::Subscriber, Error> {
        // Check to see if the action is already known and subscribe if it is.
        let subscription = self
            .try_subscribe(
                &client_operation_id,
                &action_info.unique_qualifier,
                action_info.priority,
            )
            .await
            .err_tip(|| "In RedisAwaitedActionDb::add_action")?;
        if let Some(sub) = subscription {
            return Ok(sub);
        }

        let new_operation_id = (self.operation_id_creator)();
        let awaited_action =
            AwaitedAction::new(new_operation_id.clone(), action_info, (self.now_fn)().now());
        debug_assert!(
            ActionStage::Queued == awaited_action.state().stage,
            "Expected action to be queued"
        );

        // Note: Version is not needed with this api.
        let _version = self
            .store
            .update_data(UpdateOperationIdToAwaitedAction(awaited_action))
            .await
            .err_tip(|| "In RedisAwaitedActionDb::add_action")?
            .err_tip(|| {
                "Version match failed for new action insert in RedisAwaitedActionDb::add_action"
            })?;

        self.store
            .update_data(UpdateClientIdToOperationId {
                client_operation_id: client_operation_id.clone(),
                operation_id: new_operation_id.clone(),
            })
            .await
            .err_tip(|| "In RedisAwaitedActionDb::add_action")?;

        Ok(OperationSubscriber::new(
            Some(client_operation_id),
            OperationIdToAwaitedAction(Cow::Owned(new_operation_id)),
            Arc::downgrade(&self.store),
            self.now_fn.clone(),
        ))
    }

    async fn get_range_of_actions(
        &self,
        state: SortedAwaitedActionState,
        start: Bound<SortedAwaitedAction>,
        end: Bound<SortedAwaitedAction>,
        desc: bool,
    ) -> Result<impl Stream<Item = Result<Self::Subscriber, Error>> + Send, Error> {
        if !matches!(start, Bound::Unbounded) {
            return Err(make_err!(
                Code::Unimplemented,
                "Start bound is not supported in RedisAwaitedActionDb::get_range_of_actions",
            ));
        }
        if !matches!(end, Bound::Unbounded) {
            return Err(make_err!(
                Code::Unimplemented,
                "Start bound is not supported in RedisAwaitedActionDb::get_range_of_actions",
            ));
        }
        // TODO(allada) This API is not difficult to implement, but there is no code path
        // that uses it, so no reason to implement it yet.
        if !desc {
            return Err(make_err!(
                Code::Unimplemented,
                "Descending order is not supported in RedisAwaitedActionDb::get_range_of_actions",
            ));
        }
        Ok(self
            .store
            .search_by_index_prefix(SearchStateToAwaitedAction(get_state_prefix(state)))
            .await
            .err_tip(|| "In RedisAwaitedActionDb::get_range_of_actions")?
            .map_ok(move |awaited_action| {
                OperationSubscriber::new(
                    None,
                    OperationIdToAwaitedAction(Cow::Owned(awaited_action.operation_id().clone())),
                    Arc::downgrade(&self.store),
                    self.now_fn.clone(),
                )
            }))
    }

    async fn get_all_awaited_actions(
        &self,
    ) -> Result<impl Stream<Item = Result<Self::Subscriber, Error>>, Error> {
        Ok(self
            .store
            .search_by_index_prefix(SearchStateToAwaitedAction(""))
            .await
            .err_tip(|| "In RedisAwaitedActionDb::get_range_of_actions")?
            .map_ok(move |awaited_action| {
                OperationSubscriber::new(
                    None,
                    OperationIdToAwaitedAction(Cow::Owned(awaited_action.operation_id().clone())),
                    Arc::downgrade(&self.store),
                    self.now_fn.clone(),
                )
            }))
    }
}
