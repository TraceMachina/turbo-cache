# Copyright 2022-2024 The NativeLink Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ubuntu:jammy-20240212
# https://hub.docker.com/layers/library/ubuntu/jammy-20240212/images/sha256-9089166d0211acd54441bb6a532f69e0038287edf625d62fda94784df7f07474
FROM ubuntu:22.04@sha256:ed1544e454989078f5dec1bfdabd8c5cc9c48e0705d07b678ab6ae3fb61952d2 AS dependencies
# hadolint ignore=DL3009,DL3015
RUN apt-get update && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y \
        git=1:2.34.1-1ubuntu1.11 \
        ca-certificates=20230311ubuntu0.22.04.1 \
        curl=7.81.0-1ubuntu1.17 \
        xz-utils=5.2.5-2ubuntu1 \
        python3=3.10.6-1~22.04.1 \
        unzip=6.0-26ubuntu3.2 && \
        update-ca-certificates

RUN curl -L https://go.dev/dl/go1.23.0.linux-amd64.tar.gz -o go1.23.0.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz && \
    rm go1.23.0.linux-amd64.tar.gz

# hadolint ignore=SC1091,DL4006
RUN curl -sL -o nix-installer https://install.determinate.systems/nix/nix-installer-x86_64-linux && \
    chmod +x nix-installer && \
    ./nix-installer install linux --init none --no-confirm && \
    . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh && \
    nix develop github:facebook/buck2/d76c189ed6092d7b53506b9411241680923d593b && \
    echo "export PATH=\"$(nix develop github:facebook/buck2/d76c189ed6092d7b53506b9411241680923d593b --command env | grep '^PATH=' | cut -d '=' -f 2-):/usr/local/go/bin\"" > /etc/profile.d/set_path.sh
