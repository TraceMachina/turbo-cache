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

use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use tokio::io::AsyncWrite;

pin_project! {
    /// Utility struct that counts the number of bytes sent and passes everything else through to
    /// the underlying writer.
    pub struct WriteCounter<T: AsyncWrite> {
        #[pin]
        inner: T,
        bytes_written: u64,
        failed: bool,
    }
}

impl<T: AsyncWrite> WriteCounter<T> {
    pub const fn new(inner: T) -> Self {
        WriteCounter {
            inner,
            bytes_written: 0,
            failed: false,
        }
    }

    pub const fn inner_ref(&self) -> &T {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Returns the number of bytes written.
    pub const fn get_bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub const fn did_fail(&self) -> bool {
        self.failed
    }
}

impl<T: AsyncWrite> AsyncWrite for WriteCounter<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let me = self.project();
        let result = me.inner.poll_write(cx, buf);
        match &result {
            Poll::Ready(Result::Ok(sz)) => *me.bytes_written += *sz as u64,
            Poll::Ready(Result::Err(_)) => *me.failed = true,
            _ => {}
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let me = self.project();
        me.inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let me = self.project();
        me.inner.poll_shutdown(cx)
    }
}
