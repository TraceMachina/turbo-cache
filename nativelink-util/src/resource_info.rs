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
use std::convert::AsRef;

use nativelink_error::{error_if, make_input_err, Error, ResultExt};

const ERROR_MSG: &str = concat!(
    "Expected resource_name to be of pattern ",
    "'{?instance_name/}(?uploads/{uuid}/)blobs/{?/digest_function}{/hash}/{size}{?/optional_metadata}' or ",
    "'{?instance_name/}(?uploads/{uuid}/)compressed-blobs{?/compressor}{?/digest_function}{/hash}/{size}{?/optional_metadata}'",
);
const COMPRESSORS: [&str; 4] = ["identity", "zstd", "deflate", "brotli"];
const DIGEST_FUNCTIONS: [&str; 9] = [
    "sha256",
    "sha1",
    "md5",
    "vso",
    "sha384",
    "sha512",
    "murmur3",
    "sha256tree",
    "blake3",
];

// Named struct to make the code easier to read when adding the slash size.
const SLASH_SIZE: usize = 1;

// Rules are as follows:
//
// "instance_name" may contain slashes and may contain or equal "uploads", "compressed-blobs" and "blobs".
// if is_upload is false:
// {instance_name}/               compressed-blobs/{compressor}/{digest_function/}{hash}/{size}{/optional_metadata}
// {instance_name}/               compressed-blobs/{compressor}/{digest_function/}{hash}/{size}
// {instance_name}/               blobs/                        {digest_function/}{hash}/{size}{/optional_metadata}
// {instance_name}/               blobs/                        {digest_function/}{hash}/{size}
//                                compressed-blobs/{compressor}/{digest_function/}{hash}/{size}{/optional_metadata}
//                                compressed-blobs/{compressor}/{digest_function/}{hash}/{size}
//                                blobs/                        {digest_function/}{hash}/{size}{/optional_metadata}
//                                blobs/                        {digest_function/}{hash}/{size}
// {instance_name}/               compressed-blobs/{compressor}/                  {hash}/{size}{/optional_metadata}
// {instance_name}/               compressed-blobs/{compressor}/                  {hash}/{size}
// {instance_name}/               blobs/                                          {hash}/{size}{/optional_metadata}
// {instance_name}/               blobs/                                          {hash}/{size}
//                                compressed-blobs/{compressor}/                  {hash}/{size}{/optional_metadata}
//                                compressed-blobs/{compressor}/                  {hash}/{size}
//
//                                blobs/                                          {hash}/{size}{/optional_metadata}
//                                blobs/                                          {hash}/{size}
//
// if is_upload is true:
// {instance_name}/uploads/{uuid}/compressed-blobs/{compressor}/{digest_function/}{hash}/{size}{/optional_metadata}
// {instance_name}/uploads/{uuid}/compressed-blobs/{compressor}/{digest_function/}{hash}/{size}
// {instance_name}/uploads/{uuid}/blobs/                        {digest_function/}{hash}/{size}{/optional_metadata}
// {instance_name}/uploads/{uuid}/blobs/                        {digest_function/}{hash}/{size}
//                 uploads/{uuid}/compressed-blobs/{compressor}/{digest_function/}{hash}/{size}{/optional_metadata}
//                 uploads/{uuid}/compressed-blobs/{compressor}/{digest_function/}{hash}/{size}
//                 uploads/{uuid}/blobs/                        {digest_function/}{hash}/{size}{/optional_metadata}
//                 uploads/{uuid}/blobs/                        {digest_function/}{hash}/{size}
// {instance_name}/uploads/{uuid}/compressed-blobs/{compressor}/                  {hash}/{size}{/optional_metadata}
// {instance_name}/uploads/{uuid}/compressed-blobs/{compressor}/                  {hash}/{size}
// {instance_name}/uploads/{uuid}/blobs/                                          {hash}/{size}{/optional_metadata}
// {instance_name}/uploads/{uuid}/blobs/                                          {hash}/{size}
//                 uploads/{uuid}/compressed-blobs/{compressor}/                  {hash}/{size}{/optional_metadata}
//                 uploads/{uuid}/compressed-blobs/{compressor}/                  {hash}/{size}
//                 uploads/{uuid}/blobs/                                          {hash}/{size}{/optional_metadata}
//                 uploads/{uuid}/blobs/                                          {hash}/{size}
//

// Useful utility struct for converting bazel's (uri-like path) into its parts.
#[derive(Debug, Default)]
pub struct ResourceInfo<'a> {
    pub instance_name: Cow<'a, str>,
    pub uuid: Option<Cow<'a, str>>,
    pub compressor: Option<Cow<'a, str>>,
    pub digest_function: Option<Cow<'a, str>>,
    pub hash: Cow<'a, str>,
    size: Cow<'a, str>,
    pub expected_size: usize,
    pub optional_metadata: Option<Cow<'a, str>>,
}

impl<'a> ResourceInfo<'a> {
    pub fn new(resource_name: &'a str, is_upload: bool) -> Result<ResourceInfo<'a>, Error> {
        // The most amount of slashes there can be to get to "(compressed-)blobs" section is 7.
        let mut rparts = resource_name.rsplitn(7, '/');
        let mut output = ResourceInfo::default();
        let mut end_bytes_processed = 0;
        let end_state = recursive_parse(
            &mut rparts,
            &mut output,
            State::Unknown,
            &mut end_bytes_processed,
        )
        .err_tip(|| format!("{ERROR_MSG} in {resource_name}"))?;
        error_if!(
            end_state != State::OptionalMetadata,
            "Expected the final state to be OptionalMetadata. Got: {end_state:?} for {resource_name} is_upload: {is_upload}"
        );

        // Slice off the processed parts of `resource_name`.
        let beginning_part = if end_bytes_processed == resource_name.len() {
            ""
        } else {
            &resource_name[..resource_name.len() - end_bytes_processed - SLASH_SIZE]
        };
        if !is_upload {
            output.instance_name = Cow::Borrowed(beginning_part);
            return Ok(output);
        }

        // If it's an upload, at this point it will have be:
        // `{?instance_name}/uploads/{uuid}`.
        // Remember, `instance_name` can contain slashes and/or special names
        // like "blobs" or "uploads".
        let mut parts = beginning_part.rsplitn(3, '/');
        output.uuid = Some(Cow::Borrowed(
            parts
                .next()
                .err_tip(|| format!("{ERROR_MSG} in {resource_name}"))?,
        ));
        {
            // Sanity check that our next item is "uploads".
            let uploads = parts
                .next()
                .err_tip(|| format!("{ERROR_MSG} in {resource_name}"))?;
            error_if!(
                uploads != "uploads",
                "Expected part to be 'uploads'. Got: {uploads} for {resource_name} is_upload: {is_upload}"
            );
        }

        // `instance_name` is optional.
        if let Some(instance_name) = parts.next() {
            output.instance_name = Cow::Borrowed(instance_name);
        }
        Ok(output)
    }

    /// Returns a new `ResourceInfo` with all fields owned.
    pub fn to_owned(&self) -> ResourceInfo<'static> {
        ResourceInfo {
            instance_name: Cow::Owned(self.instance_name.to_string()),
            uuid: self.uuid.as_ref().map(|uuid| Cow::Owned(uuid.to_string())),
            compressor: self
                .compressor
                .as_ref()
                .map(|compressor| Cow::Owned(compressor.to_string())),
            digest_function: self
                .digest_function
                .as_ref()
                .map(|digest_function| Cow::Owned(digest_function.to_string())),
            hash: Cow::Owned(self.hash.to_string()),
            size: Cow::Owned(self.size.to_string()),
            expected_size: self.expected_size,
            optional_metadata: self
                .optional_metadata
                .as_ref()
                .map(|optional_metadata| Cow::Owned(optional_metadata.to_string())),
        }
    }

    pub fn to_string(&self, is_upload: bool) -> String {
        [
            Some(self.instance_name.as_ref()),
            is_upload.then_some("uploads"),
            self.uuid.as_ref().map(AsRef::as_ref),
            Some(
                self.compressor
                    .as_ref()
                    .map_or("blobs", |_| "compressed-blobs"),
            ),
            self.compressor.as_ref().map(AsRef::as_ref),
            self.digest_function.as_ref().map(AsRef::as_ref),
            Some(self.hash.as_ref()),
            Some(self.size.as_ref()),
            self.optional_metadata.as_ref().map(AsRef::as_ref),
        ]
        .into_iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .collect::<Vec<&str>>()
        .join("/")
    }
}

#[derive(Debug, PartialEq)]
enum State {
    Unknown,
    Compressor,
    DigestFunction,
    Hash,
    Size,
    OptionalMetadata,
}

pub fn is_supported_digest_function(digest_function: &str) -> bool {
    DIGEST_FUNCTIONS.contains(&digest_function.to_lowercase().as_str())
}

// Iterate backwards looking for "(compressed-)blobs", once found, move forward
// populating the output struct. This recursive function utilises the stack to
// temporarily hold the reference to the previous item reducing the need for
// a heap allocation.
fn recursive_parse<'a>(
    rparts: &mut impl Iterator<Item = &'a str>,
    output: &mut ResourceInfo<'a>,
    mut state: State,
    bytes_processed: &mut usize,
) -> Result<State, Error> {
    let part = rparts.next().err_tip(|| "on rparts.next()")?;
    if state == State::Unknown {
        if part == "blobs" {
            *bytes_processed = part.len() + SLASH_SIZE;
            return Ok(State::DigestFunction);
        }
        if part == "compressed-blobs" {
            *bytes_processed = part.len() + SLASH_SIZE;
            return Ok(State::Compressor);
        }
        state = recursive_parse(rparts, output, state, bytes_processed)?;
    }

    loop {
        match state {
            State::Unknown => {
                return Err(make_input_err!(
                    "Unknown state should never be reached in ResourceInfo::new"
                ))
            }
            State::Compressor => {
                state = State::DigestFunction;
                if COMPRESSORS.contains(&part) {
                    output.compressor = Some(Cow::Borrowed(part));
                    *bytes_processed += part.len() + SLASH_SIZE;
                    return Ok(state);
                }
                return Err(make_input_err!("Expected compressor, got {part}"));
            }
            State::DigestFunction => {
                state = State::Hash;
                if DIGEST_FUNCTIONS.contains(&part) {
                    output.digest_function = Some(Cow::Borrowed(part));
                    *bytes_processed += part.len() + SLASH_SIZE;
                    return Ok(state);
                }
            }
            State::Hash => {
                output.hash = Cow::Borrowed(part);
                *bytes_processed += part.len() + SLASH_SIZE;
                // TODO(allada) Set the digest_function if it is not set based on the hash size.
                return Ok(State::Size);
            }
            State::Size => {
                output.size = Cow::Borrowed(part);
                output.expected_size = part.parse::<usize>().map_err(|_| {
                    make_input_err!(
                        "Digest size_bytes was not convertible to usize. Got: {}",
                        part
                    )
                })?;
                *bytes_processed += part.len(); // Special case {size}, so it does not count one slash.
                return Ok(State::OptionalMetadata);
            }
            State::OptionalMetadata => {
                output.optional_metadata = Some(Cow::Borrowed(part));
                *bytes_processed += part.len() + SLASH_SIZE;
                // If we get here, we are done parsing backwards and have successfully parsed
                // everything beyond the "(compressed-)blobs" section.
                return Ok(State::OptionalMetadata);
            }
        }
    }
}
