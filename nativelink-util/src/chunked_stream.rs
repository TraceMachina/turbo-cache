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

use std::collections::VecDeque;
use std::ops::Bound;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Future, Stream};
use pin_project::pin_project;

#[pin_project(project = StreamStateProj)]
enum StreamState<Fut> {
    Future(#[pin] Fut),
    Next,
}

/// Takes a range of keys and a function that returns a future that yields
/// an iterator of key-value pairs. The stream will yield all key-value pairs
/// in the range, in order and buffered. A great use case is where you need
/// to implement Stream, but to access the underlying data requires a lock,
/// but API does not require the data to be in sync with data already received.
#[pin_project]
pub struct ChunkedStream<K, T, F, E, Fut>
where
    K: Ord,
    F: FnMut(Bound<K>, Bound<K>, VecDeque<T>) -> Fut,
    Fut: Future<Output = Result<Option<((Bound<K>, Bound<K>), VecDeque<T>)>, E>>,
{
    chunk_fn: F,
    buffer: VecDeque<T>,
    start_key: Option<Bound<K>>,
    end_key: Option<Bound<K>>,
    #[pin]
    stream_state: StreamState<Fut>,
}

impl<K, T, F, E, Fut> ChunkedStream<K, T, F, E, Fut>
where
    K: Ord,
    F: FnMut(Bound<K>, Bound<K>, VecDeque<T>) -> Fut,
    Fut: Future<Output = Result<Option<((Bound<K>, Bound<K>), VecDeque<T>)>, E>>,
{
    pub const fn new(start_key: Bound<K>, end_key: Bound<K>, chunk_fn: F) -> Self {
        Self {
            chunk_fn,
            buffer: VecDeque::new(),
            start_key: Some(start_key),
            end_key: Some(end_key),
            stream_state: StreamState::Next,
        }
    }
}

impl<K, T, F, E, Fut> Stream for ChunkedStream<K, T, F, E, Fut>
where
    K: Ord,
    F: FnMut(Bound<K>, Bound<K>, VecDeque<T>) -> Fut,
    Fut: Future<Output = Result<Option<((Bound<K>, Bound<K>), VecDeque<T>)>, E>>,
{
    type Item = Result<T, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            if let Some(item) = this.buffer.pop_front() {
                return Poll::Ready(Some(Ok(item)));
            }
            match this.stream_state.as_mut().project() {
                StreamStateProj::Future(fut) => {
                    match futures::ready!(fut.poll(cx)) {
                        Ok(Some(((start, end), mut buffer))) => {
                            *this.start_key = Some(start);
                            *this.end_key = Some(end);
                            std::mem::swap(&mut buffer, this.buffer);
                        }
                        Ok(None) => return Poll::Ready(None), // End of stream.
                        Err(err) => return Poll::Ready(Some(Err(err))),
                    }
                    this.stream_state.set(StreamState::Next);
                    // Loop again.
                }
                StreamStateProj::Next => {
                    this.buffer.clear();
                    // This trick is used to recycle capacity.
                    let buffer = std::mem::take(this.buffer);
                    let start_key = this
                        .start_key
                        .take()
                        .expect("start_key should never be None");
                    let end_key = this.end_key.take().expect("end_key should never be None");
                    let fut = (this.chunk_fn)(start_key, end_key, buffer);
                    this.stream_state.set(StreamState::Future(fut));
                    // Loop again.
                }
            }
        }
    }
}
