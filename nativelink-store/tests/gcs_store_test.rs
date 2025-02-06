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
use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use futures::Stream;
use gcs_mock::{MockGcsClient, TestRequest, TestResponse};
use googleapis_tonic_google_storage_v2::google::storage::v2::{
    bidi_write_object_request, write_object_request, BidiWriteObjectRequest, ChecksummedData,
    Object, ReadObjectRequest, StartResumableWriteRequest, WriteObjectRequest, WriteObjectSpec,
};
use nativelink_config::stores::GcsSpec;
use nativelink_error::Error;
use nativelink_macro::nativelink_test;
use nativelink_store::gcs_client::client::GcsClient;
use nativelink_store::gcs_client::grpc_client::GcsGrpcClient;
use nativelink_store::gcs_store::GcsStore;
use nativelink_util::buf_channel::make_buf_channel_pair;
use nativelink_util::common::DigestInfo;
use nativelink_util::instant_wrapper::MockInstantWrapped;
use nativelink_util::origin_context::OriginContext;
use nativelink_util::spawn;
use nativelink_util::store_trait::{StoreKey, StoreLike, UploadSizeInfo};
use sha2::Digest;
use tonic::{Request, Status};

mod gcs_mock {
    use std::pin::Pin;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use bytes::{Bytes, BytesMut};
    use googleapis_tonic_google_storage_v2::google::storage::v2::{
        bidi_write_object_request, write_object_request, BidiWriteObjectResponse, ChecksummedData,
        Object, ReadObjectRequest, ReadObjectResponse, StartResumableWriteRequest,
        StartResumableWriteResponse, WriteObjectResponse,
    };
    use http::StatusCode;
    use nativelink_store::gcs_client::grpc_client::{
        BidiWriteObjectStream, GcsGrpcClient, WriteObjectStream,
    };
    use tonic::metadata::{MetadataMap, MetadataValue};
    use tonic::{Request, Response, Status, Streaming};

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct TestResponse {
        pub status: Status,
        pub metadata: MetadataMap,
        pub object: Option<Object>,
        pub data: Vec<u8>,
    }

    impl TestResponse {
        pub fn ok() -> Self {
            let mut metadata = MetadataMap::new();
            metadata.insert("x-goog-generation", MetadataValue::from_str("1").unwrap());

            Self {
                status: Status::ok(""),
                metadata,
                object: None,
                data: vec![],
            }
        }

        pub fn not_found() -> Self {
            Self {
                status: Status::new(tonic::Code::NotFound, "not found"),
                metadata: MetadataMap::new(),
                object: None,
                data: vec![],
            }
        }

        #[must_use]
        pub fn with_size(mut self, size: i64) -> Self {
            self.object = Some(Object {
                size,
                ..Default::default()
            });
            self
        }

        #[must_use]
        pub fn with_upload_id(mut self, upload_id: &str) -> Self {
            self.metadata
                .insert("upload-id", MetadataValue::try_from(upload_id).unwrap());
            self
        }

        #[must_use]
        pub fn with_data(mut self, data: Vec<u8>) -> Self {
            self.data = data;
            self
        }

        #[allow(dead_code)]
        #[must_use]
        pub fn with_status(status: Status) -> Self {
            Self {
                status,
                metadata: MetadataMap::new(),
                object: None,
                data: vec![],
            }
        }
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct TestRequest {
        pub method: &'static str,
        pub object_path: String,
        pub response: TestResponse,
    }

    // Mock Body Implementation
    #[derive(Clone)]
    struct MockBody<T: prost::Message + Clone> {
        chunks: Vec<T>,
        current: usize,
    }

    impl<T: prost::Message + Clone> MockBody<T> {
        fn new(responses: Vec<T>) -> Self {
            Self {
                chunks: responses,
                current: 0,
            }
        }

        fn encode_grpc_frame(message: &T) -> Bytes {
            let msg_bytes = message.encode_to_vec();
            let mut buf = BytesMut::with_capacity(msg_bytes.len() + 5);
            buf.extend_from_slice(&[0]); // Compression flag
            buf.extend_from_slice(&(msg_bytes.len() as u32).to_be_bytes()); // Length
            buf.extend_from_slice(&msg_bytes);
            buf.freeze()
        }
    }

    impl<T: prost::Message + Clone> http_body::Body for MockBody<T> {
        type Data = Bytes;
        type Error = Box<dyn std::error::Error + Send + Sync>;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            let this = unsafe { self.get_unchecked_mut() };
            if this.current >= this.chunks.len() {
                return Poll::Ready(None);
            }

            let response = this.chunks[this.current].clone();
            this.current += 1;
            let bytes = Self::encode_grpc_frame(&response);
            Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
        }
    }

    // Mock Client Implementation
    #[allow(dead_code)]
    #[derive(Clone)]
    pub struct MockGcsClient {
        expected_requests: Arc<Vec<TestRequest>>,
        current_request: Arc<AtomicUsize>,
        request_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockGcsClient {
        pub fn new(requests: Vec<TestRequest>) -> Self {
            Self {
                expected_requests: Arc::new(requests),
                current_request: Arc::new(AtomicUsize::new(0)),
                request_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn request_count(&self) -> usize {
            self.request_log.lock().unwrap().len()
        }

        #[allow(dead_code)]
        pub fn single_head_request(response: TestResponse) -> Self {
            Self::new(vec![TestRequest {
                method: "READ",
                object_path: String::new(),
                response,
            }])
        }

        fn log_request(&self, method: &str, object: &str) {
            self.request_log
                .lock()
                .unwrap()
                .push(format!("{method} {object}"));
        }

        fn get_expected_request(&self) -> Result<&TestRequest, Status> {
            let index = self.current_request.fetch_add(1, Ordering::SeqCst);
            self.expected_requests
                .get(index)
                .ok_or_else(|| Status::internal("No more expected requests"))
        }

        fn verify_method(&self, expected: &TestRequest, method: &str) -> Result<(), Status> {
            if expected.method != method {
                return Err(Status::internal(format!("Unexpected {method} request")));
            }
            Ok(())
        }
    }

    #[async_trait]
    impl GcsGrpcClient for MockGcsClient {
        async fn read_object(
            &mut self,
            request: Request<ReadObjectRequest>,
        ) -> Result<Response<Streaming<ReadObjectResponse>>, Status> {
            let expected = self.get_expected_request()?;
            self.verify_method(expected, "READ")?;
            self.log_request("READ", &request.get_ref().object);

            if expected.response.status.code() != tonic::Code::Ok {
                return Err(expected.response.status.clone());
            }

            let metadata_response = ReadObjectResponse {
                metadata: expected.response.object.clone(),
                checksummed_data: None,
                ..Default::default()
            };

            let data_response = ReadObjectResponse {
                metadata: None,
                checksummed_data: Some(ChecksummedData {
                    content: expected.response.data.clone(),
                    crc32c: Some(0),
                }),
                ..Default::default()
            };

            let body = MockBody::new(vec![metadata_response, data_response]);

            let streaming =
                Streaming::new_response(MockDecoder::new(), body, StatusCode::OK, None, None);

            Ok(Response::new(streaming))
        }

        async fn write_object(
            &mut self,
            request: Request<WriteObjectStream>,
        ) -> Result<Response<WriteObjectResponse>, Status> {
            let expected = self.get_expected_request()?;
            self.verify_method(expected, "WRITE")?;

            let mut stream = request.into_inner();
            let mut _total_bytes = 0;

            while let Some(write_req) = futures::StreamExt::next(&mut stream).await {
                if let Some(write_object_request::FirstMessage::WriteObjectSpec(spec)) =
                    &write_req.first_message
                {
                    if let Some(resource) = &spec.resource {
                        self.log_request("WRITE", &resource.name);
                    }
                }

                if let Some(write_object_request::Data::ChecksummedData(data)) = write_req.data {
                    _total_bytes += data.content.len();
                }
            }

            if expected.response.status.code() != tonic::Code::Ok {
                return Err(expected.response.status.clone());
            }

            Ok(Response::new(WriteObjectResponse { write_status: None }))
        }

        async fn start_resumable_write(
            &mut self,
            request: Request<StartResumableWriteRequest>,
        ) -> Result<Response<StartResumableWriteResponse>, Status> {
            let expected = self.get_expected_request()?;
            self.verify_method(expected, "START_RESUMABLE")?;

            if let Some(spec) = &request.get_ref().write_object_spec {
                if let Some(resource) = &spec.resource {
                    self.log_request("START_RESUMABLE", &resource.name);
                }
            }

            if expected.response.status.code() != tonic::Code::Ok {
                return Err(expected.response.status.clone());
            }

            let upload_id = expected
                .response
                .metadata
                .get("upload-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("test-upload-id")
                .to_string();

            Ok(Response::new(StartResumableWriteResponse { upload_id }))
        }

        async fn bidi_write_object(
            &mut self,
            request: Request<BidiWriteObjectStream>,
        ) -> Result<Response<Streaming<BidiWriteObjectResponse>>, Status> {
            let expected = self.get_expected_request()?;
            self.verify_method(expected, "BIDI_WRITE")?;

            let mut stream = request.into_inner();
            let mut _total_bytes = 0;
            let mut _upload_id = String::new();

            while let Some(write_req) = futures::StreamExt::next(&mut stream).await {
                if let Some(bidi_write_object_request::FirstMessage::UploadId(id)) =
                    &write_req.first_message
                {
                    _upload_id = id.clone();
                    self.log_request("BIDI_WRITE", &_upload_id);
                }

                if let Some(bidi_write_object_request::Data::ChecksummedData(data)) = write_req.data
                {
                    _total_bytes += data.content.len();
                }
            }

            if expected.response.status.code() != tonic::Code::Ok {
                return Err(expected.response.status.clone());
            }

            // Create mock bidi write response stream
            let responses = MockBody::new(vec![BidiWriteObjectResponse { write_status: None }]);

            let streaming = Streaming::new_response(
                MockDecoder::<BidiWriteObjectResponse>::new(),
                responses,
                StatusCode::OK,
                None,
                None,
            );

            Ok(Response::new(streaming))
        }
    }

    struct MockDecoder<T>(std::marker::PhantomData<T>);

    impl<T> MockDecoder<T> {
        fn new() -> Self {
            Self(std::marker::PhantomData)
        }
    }

    impl<T: prost::Message + Default> tonic::codec::Decoder for MockDecoder<T> {
        type Item = T;
        type Error = Status;

        fn decode(
            &mut self,
            buf: &mut tonic::codec::DecodeBuf<'_>,
        ) -> Result<Option<Self::Item>, Self::Error> {
            match T::decode(buf) {
                Ok(response) => Ok(Some(response)),
                Err(e) => Err(Status::internal(e.to_string())),
            }
        }
    }
}

// Tests
#[nativelink_test]
async fn test_mock_gcs_client_write_object() {
    let test_data = vec![1, 2, 3, 4, 5];
    let object_path = "test/write.txt";

    let expected_requests = vec![TestRequest {
        method: "WRITE",
        object_path: object_path.to_string(),
        response: TestResponse::ok().with_size(test_data.len() as i64),
    }];

    let mut mock_client = MockGcsClient::new(expected_requests);

    let write_spec = WriteObjectSpec {
        resource: Some(Object {
            name: object_path.to_string(),
            bucket: "projects/_/buckets/test-bucket".to_string(),
            size: test_data.len() as i64,
            ..Default::default()
        }),
        ..Default::default()
    };

    let init_request = WriteObjectRequest {
        first_message: Some(write_object_request::FirstMessage::WriteObjectSpec(
            write_spec,
        )),
        write_offset: 0,
        data: None,
        finish_write: false,
        ..Default::default()
    };

    let data_request = WriteObjectRequest {
        first_message: None,
        write_offset: 0,
        data: Some(write_object_request::Data::ChecksummedData(
            ChecksummedData {
                content: test_data,
                crc32c: Some(0),
            },
        )),
        finish_write: true,
        ..Default::default()
    };

    let stream = futures::stream::iter(vec![init_request, data_request]);
    let pinned_stream =
        Box::pin(stream) as Pin<Box<dyn Stream<Item = WriteObjectRequest> + Send + 'static>>;
    let request = Request::new(pinned_stream);

    let response = mock_client.write_object(request).await;
    assert!(response.is_ok());
    assert_eq!(mock_client.request_count(), 1);
}

#[nativelink_test]
async fn test_mock_gcs_client_bidi_write_object() {
    let test_data = vec![1, 2, 3, 4, 5];
    let upload_id = "test-bidi-upload-123";

    let expected_requests = vec![TestRequest {
        method: "BIDI_WRITE",
        object_path: upload_id.to_string(),
        response: TestResponse::ok().with_size(test_data.len() as i64),
    }];

    let mut mock_client = MockGcsClient::new(expected_requests);

    let init_request = BidiWriteObjectRequest {
        first_message: Some(bidi_write_object_request::FirstMessage::UploadId(
            upload_id.to_string(),
        )),
        write_offset: 0,
        finish_write: false,
        data: None,
        ..Default::default()
    };

    let data_request = BidiWriteObjectRequest {
        first_message: None,
        write_offset: 0,
        data: Some(bidi_write_object_request::Data::ChecksummedData(
            ChecksummedData {
                content: test_data,
                crc32c: Some(0),
            },
        )),
        finish_write: true,
        ..Default::default()
    };

    let stream = futures::stream::iter(vec![init_request, data_request]);
    let pinned_stream =
        Box::pin(stream) as Pin<Box<dyn Stream<Item = BidiWriteObjectRequest> + Send + 'static>>;
    let request = Request::new(pinned_stream);

    let response = mock_client.bidi_write_object(request).await;
    assert!(response.is_ok());
    assert_eq!(mock_client.request_count(), 1);
}

#[nativelink_test]
async fn test_mock_gcs_client_read_object() {
    let test_data = vec![1, 2, 3, 4, 5];
    let expected_requests = vec![TestRequest {
        method: "READ",
        object_path: "test/object.txt".to_string(),
        response: TestResponse::ok().with_size(5).with_data(test_data.clone()),
    }];

    // Create mock client
    let mut mock_client = MockGcsClient::new(expected_requests);

    // Create read request
    let request = Request::new(ReadObjectRequest {
        bucket: "projects/_/buckets/test-bucket".to_string(),
        object: "test/object.txt".to_string(),
        read_offset: 0,
        read_limit: 0,
        ..Default::default()
    });

    // Execute request
    let response = mock_client.read_object(request).await.unwrap();
    let mut stream = response.into_inner();

    // Read and verify response data
    let mut received_data = Vec::new();
    while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
        match chunk {
            Ok(msg) => {
                if let Some(checksummed_data) = msg.checksummed_data {
                    received_data.extend(checksummed_data.content);
                }
            }
            Err(e) => panic!("Stream error: {e}"),
        }
    }

    // Verify results
    assert_eq!(received_data, test_data);
    assert_eq!(mock_client.request_count(), 1);
}

#[nativelink_test]
async fn test_mock_gcs_client_not_found() {
    // Prepare test with not found response
    let expected_requests = vec![TestRequest {
        method: "READ",
        object_path: "nonexistent/file.txt".to_string(),
        response: TestResponse::not_found(),
    }];

    // Create mock client
    let mut mock_client = MockGcsClient::new(expected_requests);

    // Create read request
    let request = Request::new(ReadObjectRequest {
        bucket: "projects/_/buckets/test-bucket".to_string(),
        object: "nonexistent/file.txt".to_string(),
        read_offset: 0,
        read_limit: 0,
        ..Default::default()
    });

    // Execute request and verify not found error
    let result = mock_client.read_object(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    assert_eq!(mock_client.request_count(), 1);
}

#[nativelink_test]
async fn test_mock_gcs_client_multiple_requests() {
    // Prepare multiple test requests
    let expected_requests = vec![
        TestRequest {
            method: "READ",
            object_path: "file1.txt".to_string(),
            response: TestResponse::ok().with_data(vec![1, 2, 3]),
        },
        TestRequest {
            method: "READ",
            object_path: "file2.txt".to_string(),
            response: TestResponse::ok().with_data(vec![4, 5, 6]),
        },
    ];

    // Create mock client
    let mut mock_client = MockGcsClient::new(expected_requests);

    // Execute first request
    let request1 = Request::new(ReadObjectRequest {
        bucket: "projects/_/buckets/test-bucket".to_string(),
        object: "file1.txt".to_string(),
        read_offset: 0,
        read_limit: 0,
        ..Default::default()
    });
    let response1 = mock_client.read_object(request1).await.unwrap();
    let mut stream1 = response1.into_inner();
    let mut data1 = Vec::new();
    while let Some(chunk) = futures::StreamExt::next(&mut stream1).await {
        if let Ok(msg) = chunk {
            if let Some(checksummed_data) = msg.checksummed_data {
                data1.extend(checksummed_data.content);
            }
        }
    }

    // Execute second request
    let request2 = Request::new(ReadObjectRequest {
        bucket: "projects/_/buckets/test-bucket".to_string(),
        object: "file2.txt".to_string(),
        read_offset: 0,
        read_limit: 0,
        ..Default::default()
    });
    let response2 = mock_client.read_object(request2).await.unwrap();
    let mut stream2 = response2.into_inner();
    let mut data2 = Vec::new();
    while let Some(chunk) = futures::StreamExt::next(&mut stream2).await {
        if let Ok(msg) = chunk {
            if let Some(checksummed_data) = msg.checksummed_data {
                data2.extend(checksummed_data.content);
            }
        }
    }

    // Verify results
    assert_eq!(data1, vec![1, 2, 3]);
    assert_eq!(data2, vec![4, 5, 6]);
    assert_eq!(mock_client.request_count(), 2);
}

#[nativelink_test]
async fn test_mock_gcs_client_start_resumable_write() {
    let object_path = "test/resumable.txt";
    let upload_id = "test-upload-id-123";

    let expected_requests = vec![TestRequest {
        method: "START_RESUMABLE",
        object_path: object_path.to_string(),
        response: TestResponse::ok().with_upload_id(upload_id),
    }];

    let mut mock_client = MockGcsClient::new(expected_requests);

    let write_spec = WriteObjectSpec {
        resource: Some(Object {
            name: object_path.to_string(),
            bucket: "projects/_/buckets/test-bucket".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };

    let request = Request::new(StartResumableWriteRequest {
        write_object_spec: Some(write_spec),
        ..Default::default()
    });

    let response = mock_client.start_resumable_write(request).await.unwrap();
    assert_eq!(response.get_ref().upload_id, upload_id);
    assert_eq!(mock_client.request_count(), 1);
}

#[nativelink_test]
async fn test_has_object_found() -> Result<(), Error> {
    let mock_client = MockGcsClient::single_head_request(TestResponse::ok().with_size(512));

    std::env::set_var("GOOGLE_AUTH_TOKEN", "test-token");

    let jitter_fn = Arc::new(|d| d);
    let client =
        GcsClient::new_with_client(mock_client.clone(), &GcsSpec::default(), jitter_fn).await?;

    let store = GcsStore::new_with_client_and_jitter(
        &GcsSpec::default(),
        client,
        Arc::new(|d| d),
        MockInstantWrapped::default,
    )?;

    let store_ref = Pin::new(&*store);
    let digest = create_test_digest();
    let result = store_ref.has(&digest).await?;

    assert_eq!(result, Some(512));
    assert_eq!(mock_client.request_count(), 1);
    Ok(())
}

#[nativelink_test]
async fn test_has_object_not_found() -> Result<(), Error> {
    let mock_client = MockGcsClient::single_head_request(TestResponse::not_found());

    std::env::set_var("GOOGLE_AUTH_TOKEN", "test-token");

    let jitter_fn = Arc::new(|d| d);
    let client =
        GcsClient::new_with_client(mock_client.clone(), &GcsSpec::default(), jitter_fn).await?;

    let store = GcsStore::new_with_client_and_jitter(
        &GcsSpec::default(),
        client,
        Arc::new(|d| d),
        MockInstantWrapped::default,
    )?;

    let store_ref = Pin::new(&*store);
    let digest = create_test_digest();
    let result = store_ref.has(&digest).await?;

    assert_eq!(result, None);
    assert_eq!(mock_client.request_count(), 1);
    Ok(())
}

#[nativelink_test]
async fn test_get_part() -> Result<(), Error> {
    const VALUE: &[u8] = b"test_content";

    let mock_client = MockGcsClient::new(vec![TestRequest {
        method: "READ",
        object_path: "test-digest".to_string(),
        response: TestResponse::ok().with_data(VALUE.to_vec()),
    }]);

    std::env::set_var("GOOGLE_AUTH_TOKEN", "test-token");
    let jitter_fn = Arc::new(|d| d);
    let client =
        GcsClient::new_with_client(mock_client.clone(), &GcsSpec::default(), jitter_fn).await?;

    let store = Arc::new(GcsStore::new_with_client_and_jitter(
        &GcsSpec::default(),
        client,
        Arc::new(|d| d),
        MockInstantWrapped::default,
    )?);

    let (mut tx, rx) = make_buf_channel_pair();
    let store_clone = Arc::clone(&store);

    let get_fut = spawn!("get_part", async move {
        Pin::new(&*store_clone)
            .get_part(create_test_digest(), &mut tx, 0, None)
            .await
    });

    let read_fut = async move {
        let mut result = Vec::new();
        let mut rx = rx;
        while let Ok(Some(data)) = futures::TryStreamExt::try_next(&mut rx).await {
            result.extend_from_slice(&data);
        }
        result
    };

    let (get_result, read_result) = tokio::join!(get_fut, read_fut);
    get_result??;

    assert_eq!(read_result, VALUE);
    assert_eq!(mock_client.request_count(), 1);
    Ok(())
}

#[nativelink_test]
async fn test_get_part_with_offset_and_length() -> Result<(), Error> {
    const VALUE: &[u8] = b"test_content_with_offset_and_length";
    const OFFSET: u64 = 5;
    const LENGTH: u64 = 10;

    let mock_client = MockGcsClient::new(vec![TestRequest {
        method: "READ",
        object_path: "test-digest".to_string(),
        response: TestResponse::ok()
            .with_size(LENGTH as i64)
            .with_data(VALUE[OFFSET as usize..(OFFSET + LENGTH) as usize].to_vec()),
    }]);

    std::env::set_var("GOOGLE_AUTH_TOKEN", "test-token");
    let jitter_fn = Arc::new(|d| d);
    let client =
        GcsClient::new_with_client(mock_client.clone(), &GcsSpec::default(), jitter_fn).await?;

    let store = Arc::new(GcsStore::new_with_client_and_jitter(
        &GcsSpec::default(),
        client,
        Arc::new(|d| d),
        MockInstantWrapped::default,
    )?);

    let (mut tx, rx) = make_buf_channel_pair();
    let store_clone = Arc::clone(&store);

    let get_fut = spawn!("get_part_with_offset", async move {
        store_clone
            .get_part(create_test_digest(), &mut tx, OFFSET, Some(LENGTH))
            .await
    });

    let read_fut = async move {
        let mut result = Vec::new();
        let mut rx = rx;
        while let Ok(Some(data)) = futures::TryStreamExt::try_next(&mut rx).await {
            result.extend_from_slice(&data);
        }
        result
    };

    let (get_result, read_result) = tokio::join!(get_fut, read_fut);
    get_result??;

    assert_eq!(
        read_result,
        &VALUE[OFFSET as usize..(OFFSET + LENGTH) as usize]
    );
    assert_eq!(mock_client.request_count(), 1);
    Ok(())
}

#[nativelink_test]
async fn test_has_with_retries() -> Result<(), Error> {
    let client = MockGcsClient::new(vec![
        TestRequest {
            method: "READ",
            object_path: String::new(),
            response: TestResponse::with_status(Status::new(
                tonic::Code::Unavailable,
                "service temporarily unavailable",
            )),
        },
        TestRequest {
            method: "READ",
            object_path: String::new(),
            response: TestResponse::ok().with_size(111),
        },
    ]);

    let retry_config = nativelink_config::stores::Retry {
        max_retries: 3,
        delay: 0.0,
        jitter: 0.0,
        ..Default::default()
    };

    // Create store with retry config
    std::env::set_var("GOOGLE_AUTH_TOKEN", "test-token");
    let jitter_fn = Arc::new(|d| d);
    let gcs_client = GcsClient::new_with_client(
        client.clone(),
        &GcsSpec {
            retry: retry_config.clone(),
            ..Default::default()
        },
        jitter_fn,
    )
    .await?;

    let store = GcsStore::new_with_client_and_jitter(
        &GcsSpec {
            retry: retry_config,
            ..Default::default()
        },
        gcs_client,
        Arc::new(|d| d),
        MockInstantWrapped::default,
    )?;

    let store_ref = Pin::new(&*store);
    let result = store_ref.has(&create_test_digest()).await?;

    assert_eq!(result, Some(111));
    assert_eq!(client.request_count(), 2);
    Ok(())
}

#[nativelink_test]
async fn test_update_with_retries() -> Result<(), Error> {
    const CONTENT_LENGTH: usize = 512;

    let mut send_data = BytesMut::new();
    for i in 0..CONTENT_LENGTH {
        send_data.put_u8(((i % 93) + 33) as u8);
    }
    let send_data = send_data.freeze();

    let client = MockGcsClient::new(vec![
        TestRequest {
            method: "WRITE",
            object_path: String::new(),
            response: TestResponse::with_status(Status::new(
                tonic::Code::Unavailable,
                "service temporarily unavailable",
            )),
        },
        TestRequest {
            method: "WRITE",
            object_path: String::new(),
            response: TestResponse::ok(),
        },
    ]);

    let retry_config = nativelink_config::stores::Retry {
        max_retries: 3,
        delay: 0.0,
        jitter: 0.0,
        ..Default::default()
    };

    std::env::set_var("GOOGLE_AUTH_TOKEN", "test-token");
    let jitter_fn = Arc::new(|d| d);
    let gcs_client = GcsClient::new_with_client(
        client.clone(),
        &GcsSpec {
            retry: retry_config.clone(),
            ..Default::default()
        },
        jitter_fn,
    )
    .await?;

    let store = GcsStore::new_with_client_and_jitter(
        &GcsSpec {
            retry: retry_config,
            ..Default::default()
        },
        gcs_client,
        Arc::new(|d| d),
        MockInstantWrapped::default,
    )?;

    let (mut tx, rx) = make_buf_channel_pair();

    let update_fut = store.update(
        create_test_digest(),
        rx,
        UploadSizeInfo::ExactSize(CONTENT_LENGTH as u64),
    );

    let send_fut = async move {
        tx.send(send_data).await?;
        tx.send_eof()
    };

    let (update_result, send_result) = tokio::join!(update_fut, send_fut);

    update_result?;
    send_result?;
    assert_eq!(client.request_count(), 2);
    Ok(())
}

#[nativelink_test]
async fn test_get_part_zero_digest() -> Result<(), Error> {
    let digest = DigestInfo::new(sha2::Sha256::new().finalize().into(), 0);
    let client = MockGcsClient::new(vec![]); // Should make no requests

    std::env::set_var("GOOGLE_AUTH_TOKEN", "test-token");

    let jitter_fn = Arc::new(|d| d);
    let gcs_client =
        GcsClient::new_with_client(client.clone(), &GcsSpec::default(), jitter_fn).await?;
    let store = Arc::new(GcsStore::new_with_client_and_jitter(
        &GcsSpec::default(),
        gcs_client,
        Arc::new(|d| d),
        MockInstantWrapped::default,
    )?);

    let (mut tx, rx) = make_buf_channel_pair();
    let store_clone = Arc::clone(&store);

    let get_fut = spawn!("get_part", async move {
        Pin::new(&*store_clone)
            .get_part(digest, &mut tx, 0, None)
            .await
    });

    let read_fut = async move {
        let mut result = Vec::new();
        let mut rx = rx;
        while let Ok(Some(data)) = futures::TryStreamExt::try_next(&mut rx).await {
            result.extend_from_slice(&data);
        }
        result
    };

    let (get_result, read_result) = tokio::join!(get_fut, read_fut);

    get_result??;
    assert_eq!(read_result.len(), 0, "Expected empty file content");
    assert_eq!(
        client.request_count(),
        0,
        "Expected no requests for zero digest"
    );
    Ok(())
}

#[nativelink_test]
async fn test_multipart_upload_large_file() -> Result<(), Error> {
    const MIN_BLOCK_SIZE: usize = 4 * 1024 * 1000; // 4MB for GCS
    const TOTAL_SIZE: usize = MIN_BLOCK_SIZE * 2 + 50;

    let mut upload_data = Vec::with_capacity(TOTAL_SIZE);
    for i in 0..TOTAL_SIZE {
        upload_data.push(((i * 3) % 256) as u8);
    }

    // For GCS, we use resumable upload which requires:
    // 1. Start resumable upload request
    // 2. Bidi write request with streaming chunks
    let client = MockGcsClient::new(vec![
        TestRequest {
            method: "START_RESUMABLE",
            object_path: String::new(),
            response: TestResponse::ok().with_upload_id("test-upload-id"),
        },
        TestRequest {
            method: "BIDI_WRITE",
            object_path: String::new(),
            response: TestResponse::ok(),
        },
    ]);

    let jitter_fn = Arc::new(|d| d);
    std::env::set_var("GOOGLE_AUTH_TOKEN", "test-token");
    let gcs_client =
        GcsClient::new_with_client(client.clone(), &GcsSpec::default(), jitter_fn).await?;
    let store = GcsStore::new_with_client_and_jitter(
        &GcsSpec::default(),
        gcs_client,
        Arc::new(|d| d),
        MockInstantWrapped::default,
    )?;

    let digest = create_test_digest();
    let _origin_guard = OriginContext::new();

    store.update_oneshot(digest, upload_data.into()).await?;
    assert_eq!(client.request_count(), 2);
    Ok(())
}

fn create_test_digest<'a>() -> StoreKey<'a> {
    StoreKey::from("test-digest")
}
