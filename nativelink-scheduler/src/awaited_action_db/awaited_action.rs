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
use std::time::{SystemTime, UNIX_EPOCH};

use nativelink_error::{make_input_err, Error, ResultExt};
use nativelink_metric::{
    MetricFieldData, MetricKind, MetricPublishKnownKindData, MetricsComponent,
};
use nativelink_util::action_messages::{
    ActionInfo, ActionStage, ActionState, OperationId, WorkerId,
};
use nativelink_util::origin_context::ActiveOriginContext;
use nativelink_util::origin_event::{OriginMetadata, ORIGIN_EVENT_COLLECTOR};
use serde::{Deserialize, Serialize};
use static_assertions::{assert_eq_size, const_assert, const_assert_eq};

/// The version of the awaited action.
/// This number will always increment by one each time
/// the action is updated.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
struct AwaitedActionVersion(u64);

impl MetricsComponent for AwaitedActionVersion {
    fn publish(
        &self,
        _kind: MetricKind,
        _field_metadata: MetricFieldData,
    ) -> Result<MetricPublishKnownKindData, nativelink_metric::Error> {
        Ok(MetricPublishKnownKindData::Counter(self.0))
    }
}

/// An action that is being awaited on and last known state.
#[derive(Debug, Clone, MetricsComponent, Serialize, Deserialize)]
pub struct AwaitedAction {
    /// The current version of the action.
    #[metric(help = "The version of the AwaitedAction")]
    version: AwaitedActionVersion,

    /// The action that is being awaited on.
    #[metric(help = "The action info of the AwaitedAction")]
    action_info: Arc<ActionInfo>,

    /// The operation id of the action.
    // If you need the client operation id, it may be set in
    // ActionState::operation_id.
    #[metric(help = "The operation id of the AwaitedAction")]
    operation_id: OperationId,

    /// The currentsort key used to order the actions.
    #[metric(help = "The sort key of the AwaitedAction")]
    sort_key: AwaitedActionSortKey,

    /// The time the action was last updated.
    #[metric(help = "The last time the worker updated the AwaitedAction")]
    last_worker_updated_timestamp: SystemTime,

    /// The last time the client sent a keepalive message.
    #[metric(help = "The last time the client sent a keepalive message")]
    last_client_keepalive_timestamp: SystemTime,

    /// Worker that is currently running this action, None if unassigned.
    #[metric(help = "The worker id of the AwaitedAction")]
    worker_id: Option<WorkerId>,

    /// The current state of the action.
    #[metric(help = "The state of the AwaitedAction")]
    state: Arc<ActionState>,

    /// The origin metadata of the action.
    maybe_origin_metadata: Option<OriginMetadata>,

    /// Number of attempts the job has been tried.
    #[metric(help = "The number of attempts the AwaitedAction has been tried")]
    pub attempts: usize,
}

impl AwaitedAction {
    pub fn new(operation_id: OperationId, action_info: Arc<ActionInfo>, now: SystemTime) -> Self {
        let stage = ActionStage::Queued;
        let sort_key = AwaitedActionSortKey::new_with_unique_key(
            action_info.priority,
            &action_info.insert_timestamp,
        );
        let state = Arc::new(ActionState {
            stage,
            // Note: We don't use the real client_operation_id here because
            // the only place AwaitedAction::new should ever be called is
            // when the action is first created and this struct will be stored
            // in the database, so we don't want to accidentally leak the
            // client_operation_id to all clients.
            client_operation_id: operation_id.clone(),
            action_digest: action_info.unique_qualifier.digest(),
        });
        let maybe_origin_metadata = ActiveOriginContext::get_value(&ORIGIN_EVENT_COLLECTOR)
            .ok()
            .flatten()
            .map(|v| v.metadata.clone());

        Self {
            version: AwaitedActionVersion(0),
            action_info,
            operation_id,
            sort_key,
            attempts: 0,
            last_worker_updated_timestamp: now,
            last_client_keepalive_timestamp: now,
            maybe_origin_metadata,
            worker_id: None,
            state,
        }
    }

    pub(crate) fn version(&self) -> u64 {
        self.version.0
    }

    pub(crate) fn set_version(&mut self, version: u64) {
        self.version = AwaitedActionVersion(version);
    }

    pub(crate) fn increment_version(&mut self) {
        self.version = AwaitedActionVersion(self.version.0 + 1);
    }

    pub fn action_info(&self) -> &Arc<ActionInfo> {
        &self.action_info
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub(crate) fn sort_key(&self) -> AwaitedActionSortKey {
        self.sort_key
    }

    pub fn state(&self) -> &Arc<ActionState> {
        &self.state
    }

    pub(crate) fn maybe_origin_metadata(&self) -> Option<&OriginMetadata> {
        self.maybe_origin_metadata.as_ref()
    }

    pub(crate) fn worker_id(&self) -> Option<&WorkerId> {
        self.worker_id.as_ref()
    }

    pub(crate) fn last_worker_updated_timestamp(&self) -> SystemTime {
        self.last_worker_updated_timestamp
    }

    pub(crate) fn worker_keep_alive(&mut self, now: SystemTime) {
        self.last_worker_updated_timestamp = now;
    }

    pub(crate) fn last_client_keepalive_timestamp(&self) -> SystemTime {
        self.last_client_keepalive_timestamp
    }
    pub(crate) fn update_client_keep_alive(&mut self, now: SystemTime) {
        self.last_client_keepalive_timestamp = now;
    }

    pub(crate) fn set_client_operation_id(&mut self, client_operation_id: OperationId) {
        Arc::make_mut(&mut self.state).client_operation_id = client_operation_id;
    }

    /// Sets the worker id that is currently processing this action.
    pub(crate) fn set_worker_id(&mut self, new_maybe_worker_id: Option<WorkerId>, now: SystemTime) {
        if self.worker_id != new_maybe_worker_id {
            self.worker_id = new_maybe_worker_id;
            self.worker_keep_alive(now);
        }
    }

    /// Sets the current state of the action and updates the last worker updated timestamp.
    pub fn worker_set_state(&mut self, mut state: Arc<ActionState>, now: SystemTime) {
        std::mem::swap(&mut self.state, &mut state);
        self.worker_keep_alive(now);
    }
}

impl TryFrom<&[u8]> for AwaitedAction {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value)
            .map_err(|e| make_input_err!("{}", e.to_string()))
            .err_tip(|| "In AwaitedAction::TryFrom::&[u8]")
    }
}

/// The key used to sort the awaited actions.
///
/// The rules for sorting are as follows:
/// 1. priority of the action
/// 2. insert order of the action (lower = higher priority)
/// 3. (mostly random hash based on the action info)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct AwaitedActionSortKey(u64);

impl MetricsComponent for AwaitedActionSortKey {
    fn publish(
        &self,
        _kind: MetricKind,
        _field_metadata: MetricFieldData,
    ) -> Result<MetricPublishKnownKindData, nativelink_metric::Error> {
        Ok(MetricPublishKnownKindData::Counter(self.0))
    }
}

impl AwaitedActionSortKey {
    #[rustfmt::skip]
    const fn new(priority: i32, insert_timestamp: u32) -> Self {
        // Shift `new_priority` so [`i32::MIN`] is represented by zero.
        // This makes it so any nagative values are positive, but
        // maintains ordering.
        const MIN_I32: i64 = (i32::MIN as i64).abs();
        let priority = ((priority as i64 + MIN_I32) as u32).to_be_bytes();

        // Invert our timestamp so the larger the timestamp the lower the number.
        // This makes timestamp descending order instead of ascending.
        let timestamp = (insert_timestamp ^ u32::MAX).to_be_bytes();

        AwaitedActionSortKey(u64::from_be_bytes([
            priority[0], priority[1], priority[2], priority[3],
            timestamp[0], timestamp[1], timestamp[2], timestamp[3],
        ]))
    }

    fn new_with_unique_key(priority: i32, insert_timestamp: &SystemTime) -> Self {
        let timestamp = insert_timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        Self::new(priority, timestamp)
    }

    pub(crate) fn as_u64(self) -> u64 {
        self.0
    }
}

// Ensure the size of the sort key is the same as a `u64`.
assert_eq_size!(AwaitedActionSortKey, u64);

const_assert_eq!(
    AwaitedActionSortKey::new(0x1234_5678, 0x9abc_def0).0,
    // Note: Result has 0x12345678 + 0x80000000 = 0x92345678 because we need
    // to shift the `i32::MIN` value to be represented by zero.
    // Note: `6543210f` are the inverted bits of `9abcdef0`.
    // This effectively inverts the priority to now have the highest priority
    // be the lowest timestamps.
    AwaitedActionSortKey(0x9234_5678_6543_210f).0
);
// Ensure the priority is used as the sort key first.
const_assert!(
    AwaitedActionSortKey::new(i32::MAX, 0).0 > AwaitedActionSortKey::new(i32::MAX - 1, 0).0
);
const_assert!(AwaitedActionSortKey::new(i32::MAX - 1, 0).0 > AwaitedActionSortKey::new(1, 0).0);
const_assert!(AwaitedActionSortKey::new(1, 0).0 > AwaitedActionSortKey::new(0, 0).0);
const_assert!(AwaitedActionSortKey::new(0, 0).0 > AwaitedActionSortKey::new(-1, 0).0);
const_assert!(AwaitedActionSortKey::new(-1, 0).0 > AwaitedActionSortKey::new(i32::MIN + 1, 0).0);
const_assert!(
    AwaitedActionSortKey::new(i32::MIN + 1, 0).0 > AwaitedActionSortKey::new(i32::MIN, 0).0
);

// Ensure the insert timestamp is used as the sort key second.
const_assert!(AwaitedActionSortKey::new(0, u32::MIN).0 > AwaitedActionSortKey::new(0, u32::MAX).0);
