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

use nativelink_macro::nativelink_test;
use nativelink_util::resource_info::{is_supported_digest_function, ResourceInfo};
use pretty_assertions::assert_eq;

#[nativelink_test]
async fn read_instance_name_compressed_blobs_compressor_digest_function_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str =
        "instance_name/compressed-blobs/zstd/blake3/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_instance_name_compressed_blobs_compressor_digest_function_hash_size_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "instance_name/compressed-blobs/zstd/blake3/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_instance_name_blobs_digest_function_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "instance_name/blobs/blake3/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_instance_name_blobs_digest_function_hash_size_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "instance_name/blobs/blake3/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_compressed_blobs_compressor_digest_function_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "compressed-blobs/zstd/blake3/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_compressed_blobs_compressor_digest_function_hash_size_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "compressed-blobs/zstd/blake3/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    Ok(())
}

#[nativelink_test]
async fn read_blobs_digest_function_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "blobs/blake3/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_blobs_digest_function_hash_size_test() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "blobs/blake3/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_instance_name_compressed_blobs_compressor_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "instance_name/compressed-blobs/zstd/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_instance_name_compressed_blobs_compressor_hash_size_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "instance_name/compressed-blobs/zstd/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_instance_name_blobs_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "instance_name/blobs/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_instance_name_blobs_hash_size_test() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "instance_name/blobs/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_compressed_blobs_compressor_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "compressed-blobs/zstd/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_compressed_blobs_compressor_hash_size_test() -> Result<(), Box<dyn std::error::Error>>
{
    const RESOURCE_NAME: &str = "compressed-blobs/zstd/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_blobs_hash_size_optional_metadata_test() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "blobs/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_blobs_hash_size_test() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "blobs/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_instance_name_can_have_slashes_test() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "my/instance/name/blobs/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "my/instance/name");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_instance_name_can_be_blobs_test() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "blobs/blobs/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, false)?;
    assert_eq!(resource_info.instance_name, "blobs");
    assert_eq!(resource_info.uuid, None);
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(false));
    Ok(())
}

#[nativelink_test]
async fn read_blobs_missing() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "hash/12345";
    assert!(ResourceInfo::new(RESOURCE_NAME, false).is_err());
    Ok(())
}

#[nativelink_test]
async fn read_blobs_invalid() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "BLOBS/hash/12345";
    assert!(ResourceInfo::new(RESOURCE_NAME, false).is_err());
    Ok(())
}

#[nativelink_test]
async fn read_too_short_test() -> Result<(), Box<dyn std::error::Error>> {
    assert!(ResourceInfo::new("", false).is_err());
    assert!(ResourceInfo::new("/", false).is_err());
    assert!(ResourceInfo::new("//", false).is_err());
    assert!(ResourceInfo::new("///", false).is_err());
    assert!(ResourceInfo::new("blobs/", false).is_err());
    assert!(ResourceInfo::new("blobs//", false).is_err());
    assert!(ResourceInfo::new("blobs///", false).is_err());
    Ok(())
}

// Begin write tests.

#[nativelink_test]
async fn write_instance_name_uploads_uuid_compressed_blobs_compressor_digest_function_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str =
        "instance_name/uploads/uuid/compressed-blobs/zstd/blake3/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_instance_name_uploads_uuid_compressed_blobs_compressor_digest_function_hash_size_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str =
        "instance_name/uploads/uuid/compressed-blobs/zstd/blake3/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_instance_name_uploads_uuid_blobs_digest_function_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str =
        "instance_name/uploads/uuid/blobs/blake3/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_instance_name_uploads_uuid_blobs_digest_function_hash_size_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "instance_name/uploads/uuid/blobs/blake3/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_uploads_uuid_compressed_blobs_compressor_digest_function_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str =
        "uploads/uuid/compressed-blobs/zstd/blake3/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_uploads_uuid_compressed_blobs_compressor_digest_function_hash_size_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uploads/uuid/compressed-blobs/zstd/blake3/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_uploads_uuid_blobs_digest_function_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uploads/uuid/blobs/blake3/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_uploads_uuid_blobs_digest_function_hash_size_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uploads/uuid/blobs/blake3/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, Some(Cow::Borrowed("blake3")));
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_instance_name_uploads_uuid_compressed_blobs_compressor_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str =
        "instance_name/uploads/uuid/compressed-blobs/zstd/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_instance_name_uploads_uuid_compressed_blobs_compressor_hash_size_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "instance_name/uploads/uuid/compressed-blobs/zstd/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_instance_name_uploads_uuid_blobs_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "instance_name/uploads/uuid/blobs/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_instance_name_uploads_uuid_blobs_hash_size_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "instance_name/uploads/uuid/blobs/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "instance_name");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_uploads_uuid_compressed_blobs_compressor_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uploads/uuid/compressed-blobs/zstd/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_uploads_uuid_compressed_blobs_compressor_hash_size_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uploads/uuid/compressed-blobs/zstd/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, Some(Cow::Borrowed("zstd")));
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn compressed_blob_invalid_compression_format() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uploads/uuid/compressed-blobs/INVALID/hash/12345";
    assert!(ResourceInfo::new(RESOURCE_NAME, true).is_err());
    Ok(())
}

#[nativelink_test]
async fn write_uploads_uuid_blobs_hash_size_optional_metadata_test(
) -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uploads/uuid/blobs/hash/12345/optional_metadata";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(
        resource_info.optional_metadata,
        Some(Cow::Borrowed("optional_metadata"))
    );
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_uploads_uuid_blobs_hash_size_test() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uploads/uuid/blobs/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_instance_name_can_have_slashes_test() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "my/instance/name/uploads/uuid/blobs/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "my/instance/name");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_instance_name_can_be_blobs_test() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "blobs/uploads/uuid/blobs/hash/12345";
    let resource_info = ResourceInfo::new(RESOURCE_NAME, true)?;
    assert_eq!(resource_info.instance_name, "blobs");
    assert_eq!(resource_info.uuid, Some(Cow::Borrowed("uuid")));
    assert_eq!(resource_info.compressor, None);
    assert_eq!(resource_info.digest_function, None);
    assert_eq!(resource_info.hash, "hash");
    assert_eq!(resource_info.expected_size, 12345);
    assert_eq!(resource_info.optional_metadata, None);
    assert_eq!(RESOURCE_NAME, resource_info.to_string(true));
    Ok(())
}

#[nativelink_test]
async fn write_uploads_missing() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uuid/compressed-blobs/hash/12345";
    assert!(ResourceInfo::new(RESOURCE_NAME, true).is_err());
    Ok(())
}

#[nativelink_test]
async fn write_uploads_invalid() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "UPLOADS/uuid/compressed-blobs/hash/12345";
    assert!(ResourceInfo::new(RESOURCE_NAME, true).is_err());
    Ok(())
}

#[nativelink_test]
async fn write_uploads_blobs_missing() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uploads/uuid/hash/12345";
    assert!(ResourceInfo::new(RESOURCE_NAME, true).is_err());
    Ok(())
}

#[nativelink_test]
async fn write_uploads_blobs_invalid() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uploads/uuid/BLOBS/hash/12345";
    assert!(ResourceInfo::new(RESOURCE_NAME, true).is_err());
    Ok(())
}

#[nativelink_test]
async fn write_invalid_size_test() -> Result<(), Box<dyn std::error::Error>> {
    const RESOURCE_NAME: &str = "uploads/uuid/blobs/hash/INVALID";
    assert!(ResourceInfo::new(RESOURCE_NAME, true).is_err());
    Ok(())
}

#[nativelink_test]
async fn test_supported_digest_functions() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(is_supported_digest_function("sha256"), true);
    assert_eq!(is_supported_digest_function("sha1"), true);
    assert_eq!(is_supported_digest_function("md5"), true);
    assert_eq!(is_supported_digest_function("vso"), true);
    assert_eq!(is_supported_digest_function("sha384"), true);
    assert_eq!(is_supported_digest_function("sha512"), true);
    assert_eq!(is_supported_digest_function("murmur3"), true);
    assert_eq!(is_supported_digest_function("sha256tree"), true);
    assert_eq!(is_supported_digest_function("blake3"), true);

    Ok(())
}

#[nativelink_test]
async fn test_unsupported_digest_functions() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(is_supported_digest_function("sha3"), false);
    assert_eq!(
        is_supported_digest_function("invalid_digest_function"),
        false
    );
    assert_eq!(is_supported_digest_function("boo"), false);
    assert_eq!(is_supported_digest_function("random_hash"), false);

    Ok(())
}
