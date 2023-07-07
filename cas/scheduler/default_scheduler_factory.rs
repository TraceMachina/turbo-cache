// Copyright 2023 The Turbo Cache Authors. All rights reserved.
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

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures::Future;

use cache_lookup_scheduler::CacheLookupScheduler;
use config::schedulers::SchedulerConfig;
use error::Error;
use grpc_scheduler::GrpcScheduler;
use scheduler::{ActionScheduler, WorkerScheduler};
use simple_scheduler::SimpleScheduler;
use store::StoreManager;

pub type SchedulerFactoryResults = (Option<Arc<dyn ActionScheduler>>, Option<Arc<dyn WorkerScheduler>>);

pub fn scheduler_factory<'a>(
    scheduler_type_cfg: &'a SchedulerConfig,
    store_manager: &'a StoreManager,
    scheduler_manager: &'a HashMap<String, Arc<dyn ActionScheduler>>,
) -> Pin<Box<dyn Future<Output = Result<SchedulerFactoryResults, Error>> + 'a>> {
    Box::pin(async move {
        let scheduler: SchedulerFactoryResults = match scheduler_type_cfg {
            SchedulerConfig::simple(config) => {
                let scheduler = Arc::new(SimpleScheduler::new(&config));
                (Some(scheduler.clone()), Some(scheduler))
            }
            SchedulerConfig::grpc(config) => (Some(Arc::new(GrpcScheduler::new(&config).await?)), None),
            SchedulerConfig::cache_lookup(config) => (
                Some(Arc::new(CacheLookupScheduler::new(
                    &config,
                    &store_manager,
                    &scheduler_manager,
                )?)),
                None,
            ),
        };
        Ok(scheduler)
    })
}
