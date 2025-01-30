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

use nativelink_macro::nativelink_test;
use nativelink_proto::com::github::trace_machina::nativelink::events::{
    event, request_event, response_event, stream_event, Event, RequestEvent, ResponseEvent,
    StreamEvent,
};
use nativelink_util::origin_event::get_id_for_event;

macro_rules! event_assert {
    ($event:ident, $val:expr) => {
        assert_eq!(
            get_expected_value(&$event),
            get_id_for_event(&$event),
            "Incorrect event id for {}",
            stringify!($val)
        );
    };
}

macro_rules! test_event {
    (Request, None) => {
        let event = Event {
            event: Some(event::Event::Request(RequestEvent { event: None })),
        };
        event_assert!(event, Request(None));
    };
    (Request, $enum_type:ident) => {
        let event = Event {
            event: Some(event::Event::Request(RequestEvent {
                event: Some(request_event::Event::$enum_type(Default::default())),
            })),
        };
        event_assert!(event, Request($enum_type));
    };
    (Response, None) => {
        let event = Event {
            event: Some(event::Event::Response(ResponseEvent { event: None })),
        };
        event_assert!(event, Response(None));
    };
    (Response, $enum_type:ident) => {
        let event = Event {
            event: Some(event::Event::Response(ResponseEvent {
                event: Some(response_event::Event::$enum_type(Default::default())),
            })),
        };
        event_assert!(event, Response($enum_type));
    };
    (Stream, None) => {
        let event = Event {
            event: Some(event::Event::Stream(StreamEvent { event: None })),
        };
        event_assert!(event, Stream(None));
    };
    (Stream, $enum_type:ident) => {
        let event = Event {
            event: Some(event::Event::Stream(StreamEvent {
                event: Some(stream_event::Event::$enum_type(Default::default())),
            })),
        };
        event_assert!(event, Stream($enum_type));
    };
}

#[nativelink_test]
fn get_id_for_event_test() {
    const fn get_expected_value(event: &Event) -> [u8; 2] {
        match &event.event {
            None => [0x00, 0x00],
            Some(event::Event::Request(req)) => {
                match req.event {
                    None => [0x01, 0x00],
                    Some(request_event::Event::GetCapabilitiesRequest(_)) => [0x01, 0x01],
                    Some(request_event::Event::GetActionResultRequest(_)) => [0x01, 0x02],
                    Some(request_event::Event::UpdateActionResultRequest(_)) => [0x01, 0x03],
                    Some(request_event::Event::FindMissingBlobsRequest(_)) => [0x01, 0x04],
                    Some(request_event::Event::BatchReadBlobsRequest(_)) => [0x01, 0x05],
                    Some(request_event::Event::BatchUpdateBlobsRequest(_)) => [0x01, 0x06],
                    Some(request_event::Event::GetTreeRequest(_)) => [0x01, 0x07],
                    Some(request_event::Event::ReadRequest(_)) => [0x01, 0x08],
                    Some(request_event::Event::WriteRequest(())) => [0x01, 0x09],
                    Some(request_event::Event::QueryWriteStatusRequest(_)) => [0x01, 0x0A],
                    Some(request_event::Event::ExecuteRequest(_)) => [0x01, 0x0B],
                    Some(request_event::Event::WaitExecutionRequest(_)) => [0x01, 0x0C],
                    // Don't forget to add new entries to test cases.
                }
            }
            Some(event::Event::Response(res)) => {
                match res.event {
                    None => [0x02, 0x00],
                    Some(response_event::Event::Error(_)) => [0x02, 0x01],
                    Some(response_event::Event::ServerCapabilities(_)) => [0x02, 0x02],
                    Some(response_event::Event::ActionResult(_)) => [0x02, 0x03],
                    Some(response_event::Event::FindMissingBlobsResponse(_)) => [0x02, 0x04],
                    Some(response_event::Event::BatchReadBlobsResponse(_)) => [0x02, 0x05],
                    Some(response_event::Event::BatchUpdateBlobsResponse(_)) => [0x02, 0x06],
                    Some(response_event::Event::WriteResponse(_)) => [0x02, 0x07],
                    Some(response_event::Event::QueryWriteStatusResponse(_)) => [0x02, 0x08],
                    Some(response_event::Event::Empty(())) => [0x02, 0x09],
                    // Don't forget to add new entries to test cases.
                }
            }
            Some(event::Event::Stream(stream)) => {
                match stream.event {
                    None => [0x03, 0x00],
                    Some(stream_event::Event::Error(_)) => [0x03, 0x01],
                    Some(stream_event::Event::GetTreeResponse(_)) => [0x03, 0x02],
                    Some(stream_event::Event::DataLength(_)) => [0x03, 0x03],
                    Some(stream_event::Event::WriteRequest(_)) => [0x03, 0x04],
                    Some(stream_event::Event::Operation(_)) => [0x03, 0x05],
                    Some(stream_event::Event::Closed(())) => [0x03, 0x06],
                    // Don't forget to add new entries to test cases.
                }
            }
        }
    }

    let event = Event { event: None };
    event_assert!(event, None);

    test_event!(Request, None);
    test_event!(Request, GetCapabilitiesRequest);
    test_event!(Request, GetActionResultRequest);
    test_event!(Request, UpdateActionResultRequest);
    test_event!(Request, FindMissingBlobsRequest);
    test_event!(Request, BatchReadBlobsRequest);
    test_event!(Request, BatchUpdateBlobsRequest);
    test_event!(Request, GetTreeRequest);
    test_event!(Request, ReadRequest);
    test_event!(Request, WriteRequest);
    test_event!(Request, QueryWriteStatusRequest);
    test_event!(Request, ExecuteRequest);
    test_event!(Request, WaitExecutionRequest);

    test_event!(Response, None);
    test_event!(Response, Error);
    test_event!(Response, ServerCapabilities);
    test_event!(Response, ActionResult);
    test_event!(Response, FindMissingBlobsResponse);
    test_event!(Response, BatchReadBlobsResponse);
    test_event!(Response, BatchUpdateBlobsResponse);
    test_event!(Response, WriteResponse);
    test_event!(Response, QueryWriteStatusResponse);
    test_event!(Response, Empty);

    test_event!(Stream, None);
    test_event!(Stream, Error);
    test_event!(Stream, GetTreeResponse);
    test_event!(Stream, DataLength);
    test_event!(Stream, WriteRequest);
    test_event!(Stream, Operation);
    test_event!(Stream, Closed);
}
