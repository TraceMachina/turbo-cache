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

pub mod cas_server;
pub mod schedulers;
pub mod serde_utils;
pub mod stores;

use std::any::type_name;
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Deserialize)]
pub struct NamedConfig<Spec> {
    pub name: String,
    #[serde(flatten)]
    pub spec: Spec,
}

pub type StoreConfig = NamedConfig<crate::stores::StoreSpec>;
pub type SchedulerConfig = NamedConfig<crate::schedulers::SchedulerSpec>;

// TODO(aaronmondal): Remove all the iterator impls and the Deserializer once we
//                    fully migrate to the new config schema.
pub type StoreConfigs = NamedConfigs<crate::stores::StoreSpec>;
pub type SchedulerConfigs = NamedConfigs<crate::schedulers::SchedulerSpec>;

#[derive(Debug)]
pub struct NamedConfigs<T>(pub Vec<NamedConfig<T>>);

impl<T> NamedConfigs<T> {
    pub fn iter(&self) -> std::slice::Iter<'_, NamedConfig<T>> {
        self.0.iter()
    }
}

impl<T> IntoIterator for NamedConfigs<T> {
    type Item = NamedConfig<T>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a NamedConfigs<T> {
    type Item = &'a NamedConfig<T>;
    type IntoIter = std::slice::Iter<'a, NamedConfig<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

struct NamedConfigsVisitor<T> {
    phantom: PhantomData<T>,
}

impl<T> NamedConfigsVisitor<T> {
    const fn new() -> Self {
        NamedConfigsVisitor {
            phantom: PhantomData,
        }
    }
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for NamedConfigsVisitor<T> {
    type Value = NamedConfigs<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a sequence or map of named configs")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut vec = Vec::new();
        while let Some(config) = seq.next_element()? {
            vec.push(config);
        }
        Ok(NamedConfigs(vec))
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let config_type = if type_name::<T>().contains("StoreSpec") {
            "stores"
        } else if type_name::<T>().contains("SchedulerSpec") {
            "schedulers"
        } else {
            "stores and schedulers"
        };
        eprintln!(
            r#"
WARNING: Using deprecated map format for {config_type}. Please migrate to the new array format:

  // Old:
  "stores": {{
    "SOMESTORE": {{
      "memory": {{}}
    }}
  }},
  "schedulers": {{
    "SOMESCHEDULER": {{
      "simple": {{}}
    }}
  }}

  // New:
  "stores": [
    {{
      "name": "SOMESTORE",
      "memory": {{}}
    }}
  ],
  "schedulers": [
    {{
      "name": "SOMESCHEDULER",
      "simple": {{}}
    }}
  ]
"#
        );

        let mut map = HashMap::new();
        while let Some((key, value)) = access.next_entry()? {
            map.insert(key, value);
        }
        Ok(NamedConfigs(
            map.into_iter()
                .map(|(name, spec)| NamedConfig { name, spec })
                .collect(),
        ))
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NamedConfigs<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NamedConfigsVisitor::new())
    }
}
