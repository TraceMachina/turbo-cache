// use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
// use googleapis_tonic_google_storage_v2::google::storage::v2::storage_client::StorageClient;
use nativelink_config::stores::GCSSpec;
use nativelink_error::{make_err, Code, Error}; //ResultExt
use nativelink_metric::{
    MetricFieldData, MetricKind, MetricPublishKnownKindData, MetricsComponent,
};
use nativelink_util::buf_channel::{DropCloserReadHalf, DropCloserWriteHalf};
use nativelink_util::health_utils::{default_health_status_indicator, HealthStatusIndicator};
use nativelink_util::store_trait::{StoreDriver, StoreKey, UploadSizeInfo};
// use tonic::transport::Channel;

/// Represents a Google Cloud Platform (GCP) Store.
#[derive(Default)]
pub struct GCSStore {
    // spec: GCPSpec,
}

impl MetricsComponent for GCSStore {
    fn publish(
        &self,
        _kind: MetricKind,
        _field_metadata: MetricFieldData,
    ) -> Result<MetricPublishKnownKindData, nativelink_metric::Error> {
        Ok(MetricPublishKnownKindData::Component)
    }
}

impl GCSStore {
    pub async fn new(spec: &GCSSpec, current_time: fn() -> SystemTime) -> Result<Arc<Self>, Error> {
        // Print the spec
        println!("GCSStore spec: {spec:?}");

        // Get and print the current time
        let now = current_time();
        println!("Current time: {now:?}");

        Ok(Arc::new(Self {}))
    }
}

#[async_trait]
impl StoreDriver for GCSStore {
    async fn has_with_results(
        self: Pin<&Self>,
        _keys: &[StoreKey<'_>],
        _results: &mut [Option<u64>],
    ) -> Result<(), Error> {
        // results.iter_mut().for_each(|r| *r = None);
        Ok(())
    }

    async fn update(
        self: Pin<&Self>,
        _key: StoreKey<'_>,
        mut _reader: DropCloserReadHalf,
        _size_info: UploadSizeInfo,
    ) -> Result<(), Error> {
        // reader.drain().await.err_tip(|| "In GCPStore::update")?;
        Ok(())
    }

    async fn get_part(
        self: Pin<&Self>,
        _key: StoreKey<'_>,
        _writer: &mut DropCloserWriteHalf,
        _offset: u64,
        _length: Option<u64>,
    ) -> Result<(), Error> {
        Err(make_err!(Code::NotFound, "Not found in GCP store"))
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

default_health_status_indicator!(GCSStore);
