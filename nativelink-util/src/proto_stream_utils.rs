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
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::{Stream, StreamExt};
use nativelink_error::{error_if, make_input_err, Error, ResultExt};
use nativelink_proto::google::bytestream::{ReadResponse, WriteRequest};
use parking_lot::Mutex;
use tonic::{Status, Streaming};

use crate::resource_info::ResourceInfo;

pub struct WriteRequestStreamWrapper<T> {
    pub resource_info: ResourceInfo<'static>,
    pub bytes_received: usize,
    stream: T,
    first_msg: Option<WriteRequest>,
    write_finished: bool,
}

impl<T> Debug for WriteRequestStreamWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteRequestStreamWrapper")
            .field("resource_info", &self.resource_info)
            .field("bytes_received", &self.bytes_received)
            .field("first_msg", &self.first_msg)
            .field("write_finished", &self.write_finished)
            .finish()
    }
}

impl<T, E> WriteRequestStreamWrapper<T>
where
    T: Stream<Item = Result<WriteRequest, E>> + Unpin,
    E: Into<Error>,
{
    pub async fn from(mut stream: T) -> Result<WriteRequestStreamWrapper<T>, Error> {
        let first_msg = stream
            .next()
            .await
            .err_tip(|| "Error receiving first message in stream")?
            .err_tip(|| "Expected WriteRequest struct in stream")?;

        let resource_info = ResourceInfo::new(&first_msg.resource_name, true)
            .err_tip(|| {
                format!(
                    "Could not extract resource info from first message of stream: {}",
                    first_msg.resource_name
                )
            })?
            .to_owned();

        Ok(WriteRequestStreamWrapper {
            resource_info,
            bytes_received: 0,
            stream,
            first_msg: Some(first_msg),
            write_finished: false,
        })
    }

    pub async fn next(&mut self) -> Option<Result<WriteRequest, Error>> {
        futures::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    pub const fn is_first_msg(&self) -> bool {
        self.first_msg.is_some()
    }
}

impl<T, E> Stream for WriteRequestStreamWrapper<T>
where
    E: Into<Error>,
    T: Stream<Item = Result<WriteRequest, E>> + Unpin,
{
    type Item = Result<WriteRequest, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // If the stream said that the previous message was the last one, then
        // return a stream EOF (i.e. None).
        if self.write_finished {
            error_if!(
                self.bytes_received != self.resource_info.expected_size,
                "Did not send enough data. Expected {}, but so far received {}",
                self.resource_info.expected_size,
                self.bytes_received
            );
            return Poll::Ready(None);
        }

        // Gets the next message, this is either the cached first or a
        // subsequent message from the wrapped Stream.
        let maybe_message = if let Some(first_msg) = self.first_msg.take() {
            Ok(first_msg)
        } else {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(maybe_message)) => maybe_message
                    .err_tip(|| format!("Stream error at byte {}", self.bytes_received)),
                Poll::Ready(None) => Err(make_input_err!("Expected WriteRequest struct in stream")),
            }
        };

        // If we successfully got a message, update our internal state with the
        // message meta data.
        Poll::Ready(Some(maybe_message.and_then(|message| {
            self.write_finished = message.finish_write;
            self.bytes_received += message.data.len();

            // Check that we haven't read past the expected end.
            if self.bytes_received > self.resource_info.expected_size {
                Err(make_input_err!(
                    "Sent too much data. Expected {}, but so far received {}",
                    self.resource_info.expected_size,
                    self.bytes_received
                ))
            } else {
                Ok(message)
            }
        })))
    }
}

/// This provides a buffer for the first response from GrpcStore.read in order
/// to allow the first read to occur within the retry loop.  That means that if
/// the connection establishes fine, but reading the first byte of the file
/// fails we have the ability to retry before returning to the caller.
pub struct FirstStream {
    /// Contains the first response from the stream (which could be an EOF,
    /// hence the nested Option).  This should be populated on creation and
    /// returned as the first result from the stream.  Subsequent reads from the
    /// stream will use the encapsulated stream.
    first_response: Option<Option<ReadResponse>>,
    /// The stream to get responses from when `first_response` is None.
    stream: Streaming<ReadResponse>,
}

impl FirstStream {
    pub const fn new(
        first_response: Option<ReadResponse>,
        stream: Streaming<ReadResponse>,
    ) -> Self {
        Self {
            first_response: Some(first_response),
            stream,
        }
    }
}

impl Stream for FirstStream {
    type Item = Result<ReadResponse, Status>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if let Some(first_response) = self.first_response.take() {
            return std::task::Poll::Ready(first_response.map(Ok));
        }
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

/// This structure wraps all of the information required to perform a write
/// request on the `GrpcStore`.  It stores the last message retrieved which allows
/// the write to resume since the UUID allows upload resume at the server.
pub struct WriteState<T, E>
where
    T: Stream<Item = Result<WriteRequest, E>> + Unpin + Send + 'static,
    E: Into<Error> + 'static,
{
    instance_name: String,
    read_stream_error: Option<Error>,
    read_stream: WriteRequestStreamWrapper<T>,
    // Tonic doesn't appear to report an error until it has taken two messages,
    // therefore we are required to buffer the last two messages.
    cached_messages: [Option<WriteRequest>; 2],
    // When resuming after an error, the previous messages are cloned into this
    // queue upfront to allow them to be served back.
    resume_queue: [Option<WriteRequest>; 2],
    // An optimisation to avoid having to manage resume_queue when it's empty.
    is_resumed: bool,
}

impl<T, E> WriteState<T, E>
where
    T: Stream<Item = Result<WriteRequest, E>> + Unpin + Send + 'static,
    E: Into<Error> + 'static,
{
    pub const fn new(instance_name: String, read_stream: WriteRequestStreamWrapper<T>) -> Self {
        Self {
            instance_name,
            read_stream_error: None,
            read_stream,
            cached_messages: [None, None],
            resume_queue: [None, None],
            is_resumed: false,
        }
    }

    fn push_message(&mut self, message: WriteRequest) {
        self.cached_messages.swap(0, 1);
        self.cached_messages[0] = Some(message);
    }

    fn resumed_message(&mut self) -> Option<WriteRequest> {
        if self.is_resumed {
            // The resume_queue is a circular buffer, that we have to shift,
            // since its only got two elements its a trivial swap.
            self.resume_queue.swap(0, 1);
            let message = self.resume_queue[0].take();
            if message.is_none() {
                self.is_resumed = false;
            }
            message
        } else {
            None
        }
    }

    pub const fn can_resume(&self) -> bool {
        self.read_stream_error.is_none()
            && (self.cached_messages[0].is_some() || self.read_stream.is_first_msg())
    }

    pub fn resume(&mut self) {
        self.resume_queue.clone_from(&self.cached_messages);
        self.is_resumed = true;
    }

    pub fn take_read_stream_error(&mut self) -> Option<Error> {
        self.read_stream_error.take()
    }
}

/// A wrapper around `WriteState` to allow it to be reclaimed from the underlying
/// write call in the case of failure.
pub struct WriteStateWrapper<T, E>
where
    T: Stream<Item = Result<WriteRequest, E>> + Unpin + Send + 'static,
    E: Into<Error> + 'static,
{
    shared_state: Arc<Mutex<WriteState<T, E>>>,
}

impl<T, E> WriteStateWrapper<T, E>
where
    T: Stream<Item = Result<WriteRequest, E>> + Unpin + Send + 'static,
    E: Into<Error> + 'static,
{
    pub const fn new(shared_state: Arc<Mutex<WriteState<T, E>>>) -> Self {
        Self { shared_state }
    }
}

impl<T, E> Stream for WriteStateWrapper<T, E>
where
    T: Stream<Item = Result<WriteRequest, E>> + Unpin + Send + 'static,
    E: Into<Error> + 'static,
{
    type Item = WriteRequest;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        const IS_UPLOAD_TRUE: bool = true;

        // This should be an uncontended lock since write was called.
        let mut local_state = self.shared_state.lock();
        // If this is the first or second call after a failure and we have
        // cached messages, then use the cached write requests.
        let cached_message = local_state.resumed_message();
        if cached_message.is_some() {
            return Poll::Ready(cached_message);
        }
        // Read a new write request from the downstream.
        let Poll::Ready(maybe_message) = Pin::new(&mut local_state.read_stream).poll_next(cx)
        else {
            return Poll::Pending;
        };
        // Update the instance name in the write request and forward it on.
        let result = match maybe_message {
            Some(Ok(mut message)) => {
                if !message.resource_name.is_empty() {
                    // Replace the instance name in the resource name if it is
                    // different from the instance name in the write state.
                    match ResourceInfo::new(&message.resource_name, IS_UPLOAD_TRUE) {
                        Ok(mut resource_name) => {
                            if resource_name.instance_name != local_state.instance_name {
                                resource_name.instance_name =
                                    Cow::Borrowed(&local_state.instance_name);
                                message.resource_name = resource_name.to_string(IS_UPLOAD_TRUE);
                            }
                        }
                        Err(err) => {
                            local_state.read_stream_error = Some(err);
                            return Poll::Ready(None);
                        }
                    }
                }
                // Cache the last request in case there is an error to allow
                // the upload to be resumed.
                local_state.push_message(message.clone());
                Some(message)
            }
            Some(Err(err)) => {
                local_state.read_stream_error = Some(err);
                None
            }
            None => None,
        };
        Poll::Ready(result)
    }
}
