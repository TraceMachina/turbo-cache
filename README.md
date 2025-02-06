<div id="logo" align="center">
  <a href="https://www.nativelink.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="web/platform/src/assets/logo-dark.svg" />
      <source media="(prefers-color-scheme: light)" srcset="web/platform/src/assets/logo-light.svg" />
      <img alt="NativeLink" src="web/platform/src/assets/logo-light.svg" width="376" height="100" />
    </picture>
  </a>
  <img referrerpolicy="no-referrer-when-downgrade" src="https://nativelink.matomo.cloud/matomo.php?idsite=2&amp;rec=1&amp;action_name=Readme.md" style="border:0" alt="" />
  <br />
</div>

<div id="description" align="center">
  enter the shipstorm
</div>

<br />


<div id="badges" align="center">

  [![Homepage](https://img.shields.io/badge/Homepage-8A2BE2)](https://nativelink.com)
  [![GitHub stars](https://img.shields.io/github/stars/tracemachina/nativelink?style=social)](https://github.com/TraceMachina/nativelink)
  [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/TraceMachina/nativelink/badge)](https://securityscorecards.dev/viewer/?uri=github.com/TraceMachina/nativelink)
  [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8050/badge)](https://www.bestpractices.dev/projects/8050)
  [![Slack](https://img.shields.io/badge/slack--channel-blue?logo=slack)](https://nativelink.slack.com/join/shared_invite/zt-281qk1ho0-krT7HfTUIYfQMdwflRuq7A#/shared-invite/email)
  [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
</div>

## What's NativeLink?

NativeLink is an efficient, high-performance build cache and remote execution system that accelerates software compilation and testing while reducing infrastructure costs. It optimizes build processes for projects of all sizes by intelligently caching build artifacts and distributing tasks across multiple machines.

NativeLink is trusted in production environments to reduce costs and developer iteration times--handling over **one billion requests** per month for its customers, including large corporations such as **Samsung**.

<p align="center">
  <a href="https://www.youtube.com/watch?v=WLpqFuyLMUQ">
      <img src="https://trace-github-resources.s3.us-east-2.amazonaws.com/harper-90-thumbnail.webp" alt="NativeLink Explained in 90 seconds" loading="lazy" width="480" />
  </a>
</p>

## 🔑 Key Features

1. **Advanced Build Cache**:
   - Stores and reuses results of previous build steps for unchanged components
   - Significantly reduces build times, especially for incremental changes

2. **Efficient Remote Execution**:
   - Distributes build and test tasks across a network of machines
   - Parallelizes workloads for faster completion
   - Utilizes remote resources to offload computational burden from local machines
   - Ensures consistency with a uniform, controlled build environment

NativeLink seamlessly integrates with build tools that use the Remote Execution protocol, such as [Bazel](https://bazel.build), [Buck2](https://buck2.build), [Goma](https://chromium.googlesource.com/infra/goma/client/), and [Reclient](https://github.com/bazelbuild/reclient). It supports Unix-based operating systems and Windows, ensuring broad compatibility across different development environments.

## 🚀 Quickstart

To start, you can deploy NativeLink as a Docker image (as shown below) or by using our cloud-hosted solution, [NativeLink Cloud](https://app.nativelink.com). It's **FREE** for individuals, open-source projects, and cloud production environments, with support for unlimited team members.

The setups below are **production-grade** installations. See the [contribution docs](https://nativelink.com/docs/contribute/nix/) for instructions on how to build from source with [Bazel](https://nativelink.com/docs/contribute/bazel/), [Cargo](https://nativelink.com/docs/contribute/cargo/), and [Nix](https://nativelink.com/docs/contribute/nix/).

You can find a few example deployments in the [Docs](https://nativelink.com/docs/deployment-examples/kubernetes).

### 📦 Prebuilt images

Fast to spin up, but currently limited to `x86_64` systems. See the [container
registry](https://github.com/TraceMachina/nativelink/pkgs/container/nativelink)
for all image tags and the [contribution docs](https://nativelink.com/docs/contribute/nix)
for how to build the images yourself.

**Linux x86_64**

```bash
curl -O \
    https://raw.githubusercontent.com/TraceMachina/nativelink/main/nativelink-config/examples/basic_cas.json5

# See https://github.com/TraceMachina/nativelink/pkgs/container/nativelink
# to find the latest tag
docker run \
    -v $(pwd)/basic_cas.json5:/config \
    -p 50051:50051 \
    ghcr.io/tracemachina/nativelink:v0.5.4 \
    config
```

**Windows x86_64**

```powershell
# Download the configuration file
Invoke-WebRequest `
    -Uri "https://raw.githubusercontent.com/TraceMachina/nativelink/main/nativelink-config/examples/basic_cas.json5" `
    -OutFile "basic_cas.json5"

# Run the Docker container
# Note: Adjust the path if the script is not run from the directory containing basic_cas.json
docker run `
    -v ${PWD}/basic_cas.json5:/config `
    -p 50051:50051 `
    ghcr.io/tracemachina/nativelink:v0.5.4 `
    config
```

### ❄️ Raw executable with Nix

Slower, since it's built from source, but more flexible and supports MacOS.
Doesn't support native Windows, but works in WSL2.

Make sure your Nix version is recent and supports flakes. For instance, install
it via the [next-gen nix installer](https://github.com/NixOS/experimental-nix-installer).

> [!CAUTION]
> Executables built for MacOS are dynamically linked against libraries from Nix
> and won't work on systems that don't have these libraries present.

**Linux, MacOS, WSL2**

```bash
curl -O \
    https://raw.githubusercontent.com/TraceMachina/nativelink/main/nativelink-config/examples/basic_cas.json5

nix run github:TraceMachina/nativelink ./basic_cas.json5
```

See the [contribution docs](https://nativelink.com/docs/contribute/nix) for further information.

## ✍️ Contributors

<a href="https://github.com/tracemachina/nativelink/graphs/contributors" aria-label="View contributors of the NativeLink project on GitHub">
  <img src="https://contrib.rocks/image?repo=tracemachina/nativelink" alt="NativeLink contributors" loading="lazy" />
</a>

## 🤝 Contributing

Visit our [Contributing](https://github.com/tracemachina/nativelink/blob/main/CONTRIBUTING.md) guide to learn how to contribute to NativeLink. We welcome contributions from developers of all skill levels and backgrounds!

## 📊 Stats

![Alt](https://repobeats.axiom.co/api/embed/d8bfc6d283632c060beaab1e69494c2f7774a548.svg "Repobeats analytics image")

## 📜 License

Copyright 2020–2024 Trace Machina, Inc.

Licensed under the Apache 2.0 License, SPDX identifier `Apache-2.0`.
