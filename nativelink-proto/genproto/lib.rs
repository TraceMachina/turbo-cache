// Copyright 2022 The NativeLink Authors. All rights reserved.
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

// *** DO NOT MODIFY ***
// This file is auto-generated. To update it, run:
// `bazel run nativelink-proto:update_protos`

#![allow(
    clippy::default_trait_access,
    clippy::doc_lazy_continuation,
    clippy::doc_markdown,
    clippy::doc_markdown,
    clippy::large_enum_variant,
    clippy::missing_const_for_fn,
    rustdoc::invalid_html_tags
)]

pub mod build {
    pub mod bazel {
        pub mod remote {
            pub mod execution {
                pub mod v2 {
                    include!("build.bazel.remote.execution.v2.pb.rs");
                }
            }
        }
        pub mod semver {
            include!("build.bazel.semver.pb.rs");
        }
    }
}
pub mod com {
    pub mod github {
        pub mod trace_machina {
            pub mod nativelink {
                pub mod remote_execution {
                    include!("com.github.trace_machina.nativelink.remote_execution.pb.rs");
                }
                pub mod events {
                    include!("com.github.trace_machina.nativelink.events.pb.rs");
                }
            }
        }
    }
}
pub mod google {
    pub mod api {
        include!("google.api.pb.rs");
    }
    pub mod bytestream {
        include!("google.bytestream.pb.rs");
    }
    pub mod devtools {
        pub mod build {
            pub mod v1 {
                include!("google.devtools.build.v1.pb.rs");
            }
        }
    }
    pub mod longrunning {
        include!("google.longrunning.pb.rs");
    }
    pub mod rpc {
        include!("google.rpc.pb.rs");
    }
}
pub mod build_event_stream {
    include!("build_event_stream.pb.rs");
}
pub mod command_line {
    include!("command_line.pb.rs");
}
pub mod devtools {
    pub mod build {
        pub mod lib {
            pub mod packages {
                pub mod metrics {
                    include!("devtools.build.lib.packages.metrics.pb.rs");
                }
            }
        }
    }
}
pub mod blaze {
    include!("blaze.pb.rs");
    pub mod invocation_policy {
        include!("blaze.invocation_policy.pb.rs");
    }
    pub mod strategy_policy {
        include!("blaze.strategy_policy.pb.rs");
    }
}
pub mod options {
    include!("options.pb.rs");
}
pub mod failure_details {
    include!("failure_details.pb.rs");
}
