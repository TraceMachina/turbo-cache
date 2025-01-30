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
use std::ffi::{OsStr, OsString};
use std::fmt::{Debug, Formatter};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use async_lock::RwLock;
use async_trait::async_trait;
use bytes::BytesMut;
use filetime::{set_file_atime, FileTime};
use futures::stream::{StreamExt, TryStreamExt};
use futures::{Future, TryFutureExt};
use nativelink_config::stores::FilesystemSpec;
use nativelink_error::{make_err, make_input_err, Code, Error, ResultExt};
use nativelink_metric::MetricsComponent;
use nativelink_util::buf_channel::{
    make_buf_channel_pair, DropCloserReadHalf, DropCloserWriteHalf,
};
use nativelink_util::common::{fs, DigestInfo};
use nativelink_util::evicting_map::{EvictingMap, LenEntry};
use nativelink_util::health_utils::{HealthRegistryBuilder, HealthStatus, HealthStatusIndicator};
use nativelink_util::store_trait::{
    StoreDriver, StoreKey, StoreKeyBorrow, StoreOptimizations, UploadSizeInfo,
};
use nativelink_util::{background_spawn, spawn_blocking};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tokio::time::{sleep, timeout, Sleep};
use tokio_stream::wrappers::ReadDirStream;
use tracing::{event, Level};

use crate::cas_utils::is_zero_digest;

// Default size to allocate memory of the buffer when reading files.
const DEFAULT_BUFF_SIZE: usize = 32 * 1024;
// Default block size of all major filesystems is 4KB
const DEFAULT_BLOCK_SIZE: u64 = 4 * 1024;

pub const STR_FOLDER: &str = "s";
pub const DIGEST_FOLDER: &str = "d";

#[derive(Clone, Copy, Debug)]
pub enum FileType {
    Digest,
    String,
}

#[derive(Debug, MetricsComponent)]
pub struct SharedContext {
    // Used in testing to know how many active drop() spawns are running.
    // TODO(allada) It is probably a good idea to use a spin lock during
    // destruction of the store to ensure that all files are actually
    // deleted (similar to how it is done in tests).
    #[metric(help = "Number of active drop spawns")]
    pub active_drop_spawns: AtomicU64,
    #[metric(help = "Path to the configured temp path")]
    temp_path: String,
    #[metric(help = "Path to the configured content path")]
    content_path: String,
}

#[derive(Eq, PartialEq, Debug)]
enum PathType {
    Content,
    Temp,
    Custom(OsString),
}

/// [`EncodedFilePath`] stores the path to the file
/// including the context, path type and key to the file.
/// The whole [`StoreKey`] is stored as opposed to solely
/// the [`DigestInfo`] so that it is more usable for things
/// such as BEP -see Issue #1108
pub struct EncodedFilePath {
    shared_context: Arc<SharedContext>,
    path_type: PathType,
    key: StoreKey<'static>,
}

impl EncodedFilePath {
    #[inline]
    fn get_file_path(&self) -> Cow<'_, OsStr> {
        get_file_path_raw(&self.path_type, self.shared_context.as_ref(), &self.key)
    }
}

#[inline]
fn get_file_path_raw<'a>(
    path_type: &'a PathType,
    shared_context: &SharedContext,
    key: &StoreKey<'a>,
) -> Cow<'a, OsStr> {
    let folder = match path_type {
        PathType::Content => &shared_context.content_path,
        PathType::Temp => &shared_context.temp_path,
        PathType::Custom(path) => return Cow::Borrowed(path),
    };
    Cow::Owned(to_full_path_from_key(folder, key))
}

impl Drop for EncodedFilePath {
    fn drop(&mut self) {
        // `drop()` can be called during shutdown, so we use `path_type` flag to know if the
        // file actually needs to be deleted.
        if self.path_type == PathType::Content {
            return;
        }

        let file_path = self.get_file_path().to_os_string();
        let shared_context = self.shared_context.clone();
        shared_context
            .active_drop_spawns
            .fetch_add(1, Ordering::Relaxed);
        background_spawn!("filesystem_delete_file", async move {
            let result = fs::remove_file(&file_path)
                .await
                .err_tip(|| format!("Failed to remove file {file_path:?}"));
            if let Err(err) = result {
                event!(Level::ERROR, ?file_path, ?err, "Failed to delete file",);
            } else {
                event!(Level::INFO, ?file_path, "File deleted",);
            }
            shared_context
                .active_drop_spawns
                .fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// This creates the file path from the [`StoreKey`]. If
/// it is a string, the string, prefixed with [`STR_PREFIX`]
/// for backwards compatibility, is stored.
///
/// If it is a [`DigestInfo`], it is prefixed by [`DIGEST_PREFIX`]
/// followed by the string representation of a digest - the hash in hex,
/// a hyphen then the size in bytes
///
/// Previously, only the string representation of the [`DigestInfo`] was
/// used with no prefix
#[inline]
fn to_full_path_from_key(folder: &str, key: &StoreKey<'_>) -> OsString {
    match key {
        StoreKey::Str(str) => format!("{folder}/{STR_FOLDER}/{str}"),
        StoreKey::Digest(digest_info) => format!("{folder}/{DIGEST_FOLDER}/{digest_info}"),
    }
    .into()
}

pub trait FileEntry: LenEntry + Send + Sync + Debug + 'static {
    /// Responsible for creating the underlying `FileEntry`.
    fn create(data_size: u64, block_size: u64, encoded_file_path: RwLock<EncodedFilePath>) -> Self;

    /// Creates a (usually) temp file, opens it and returns the path to the temp file.
    fn make_and_open_file(
        block_size: u64,
        encoded_file_path: EncodedFilePath,
    ) -> impl Future<Output = Result<(Self, fs::ResumeableFileSlot, OsString), Error>> + Send
    where
        Self: Sized;

    /// Returns the underlying reference to the size of the data in bytes
    fn data_size_mut(&mut self) -> &mut u64;

    /// Returns the actual size of the underlying file on the disk after accounting for filesystem block size.
    fn size_on_disk(&self) -> u64;

    /// Gets the underlying `EncodedfilePath`.
    fn get_encoded_file_path(&self) -> &RwLock<EncodedFilePath>;

    /// Returns a reader that will read part of the underlying file.
    fn read_file_part(
        &self,
        offset: u64,
        length: u64,
    ) -> impl Future<Output = Result<fs::ResumeableFileSlot, Error>> + Send;

    /// This function is a safe way to extract the file name of the underlying file. To protect users from
    /// accidentally creating undefined behavior we encourage users to do the logic they need to do with
    /// the filename inside this function instead of extracting the filename and doing the logic outside.
    /// This is because the filename is not guaranteed to exist after this function returns, however inside
    /// the callback the file is always guaranteed to exist and immutable.
    /// DO NOT USE THIS FUNCTION TO EXTRACT THE FILENAME AND STORE IT FOR LATER USE.
    fn get_file_path_locked<
        T,
        Fut: Future<Output = Result<T, Error>> + Send,
        F: FnOnce(OsString) -> Fut + Send,
    >(
        &self,
        handler: F,
    ) -> impl Future<Output = Result<T, Error>> + Send;
}

pub struct FileEntryImpl {
    data_size: u64,
    block_size: u64,
    encoded_file_path: RwLock<EncodedFilePath>,
}

impl FileEntryImpl {
    pub fn get_shared_context_for_test(&mut self) -> Arc<SharedContext> {
        self.encoded_file_path.get_mut().shared_context.clone()
    }
}

impl FileEntry for FileEntryImpl {
    fn create(data_size: u64, block_size: u64, encoded_file_path: RwLock<EncodedFilePath>) -> Self {
        Self {
            data_size,
            block_size,
            encoded_file_path,
        }
    }

    /// This encapsulates the logic for the edge case of if the file fails to create
    /// the cleanup of the file is handled without creating a `FileEntry`, which would
    /// try to cleanup the file as well during `drop()`.
    async fn make_and_open_file(
        block_size: u64,
        encoded_file_path: EncodedFilePath,
    ) -> Result<(FileEntryImpl, fs::ResumeableFileSlot, OsString), Error> {
        let temp_full_path = encoded_file_path.get_file_path().to_os_string();
        let temp_file_result = fs::create_file(temp_full_path.clone())
            .or_else(|mut err| async {
                let remove_result = fs::remove_file(&temp_full_path).await.err_tip(|| {
                    format!("Failed to remove file {temp_full_path:?} in filesystem store")
                });
                if let Err(remove_err) = remove_result {
                    err = err.merge(remove_err);
                }
                event!(
                    Level::WARN,
                    ?err,
                    ?block_size,
                    ?temp_full_path,
                    "Failed to create file",
                );
                Err(err)
                    .err_tip(|| format!("Failed to create {temp_full_path:?} in filesystem store"))
            })
            .await?;

        Ok((
            <FileEntryImpl as FileEntry>::create(
                0, /* Unknown yet, we will fill it in later */
                block_size,
                RwLock::new(encoded_file_path),
            ),
            temp_file_result,
            temp_full_path,
        ))
    }

    fn data_size_mut(&mut self) -> &mut u64 {
        &mut self.data_size
    }

    fn size_on_disk(&self) -> u64 {
        self.data_size.div_ceil(self.block_size) * self.block_size
    }

    fn get_encoded_file_path(&self) -> &RwLock<EncodedFilePath> {
        &self.encoded_file_path
    }

    async fn read_file_part(
        &self,
        offset: u64,
        length: u64,
    ) -> Result<fs::ResumeableFileSlot, Error> {
        let (mut file, full_content_path_for_debug_only) = self
            .get_file_path_locked(|full_content_path| async move {
                let file = fs::open_file(full_content_path.clone(), length)
                    .await
                    .err_tip(|| {
                        format!("Failed to open file in filesystem store {full_content_path:?}")
                    })?;
                Ok((file, full_content_path))
            })
            .await?;

        file.as_reader()
            .await
            .err_tip(|| "Could not seek file in read_file_part()")?
            .get_mut()
            .seek(SeekFrom::Start(offset))
            .await
            .err_tip(|| format!("Failed to seek file: {full_content_path_for_debug_only:?}"))?;
        Ok(file)
    }

    async fn get_file_path_locked<
        T,
        Fut: Future<Output = Result<T, Error>> + Send,
        F: FnOnce(OsString) -> Fut + Send,
    >(
        &self,
        handler: F,
    ) -> Result<T, Error> {
        let encoded_file_path = self.get_encoded_file_path().read().await;
        handler(encoded_file_path.get_file_path().to_os_string()).await
    }
}

impl Debug for FileEntryImpl {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("FileEntryImpl")
            .field("data_size", &self.data_size)
            .field("encoded_file_path", &"<behind mutex>")
            .finish()
    }
}

fn make_temp_digest(mut digest: DigestInfo) -> DigestInfo {
    static DELETE_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hash = *digest.packed_hash();
    hash[24..].clone_from_slice(
        &DELETE_FILE_COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .to_le_bytes(),
    );
    digest.set_packed_hash(*hash);
    digest
}

fn make_temp_key(key: &StoreKey) -> StoreKey<'static> {
    StoreKey::Digest(make_temp_digest(key.borrow().into_digest()))
}

impl LenEntry for FileEntryImpl {
    #[inline]
    fn len(&self) -> u64 {
        self.size_on_disk()
    }

    fn is_empty(&self) -> bool {
        self.data_size == 0
    }

    #[inline]
    async fn touch(&self) -> bool {
        let result = self
            .get_file_path_locked(move |full_content_path| async move {
                let full_content_path = full_content_path.clone();
                spawn_blocking!("filesystem_touch_set_mtime", move || {
                    set_file_atime(&full_content_path, FileTime::now()).err_tip(|| {
                        format!("Failed to touch file in filesystem store {full_content_path:?}")
                    })
                })
                .await
                .map_err(|e| {
                    make_err!(
                        Code::Internal,
                        "Failed to change atime of file due to spawn failing {:?}",
                        e
                    )
                })?
            })
            .await;
        if let Err(err) = result {
            event!(Level::ERROR, ?err, "Failed to touch file",);
            return false;
        }
        true
    }

    // unref() only triggers when an item is removed from the eviction_map. It is possible
    // that another place in code has a reference to `FileEntryImpl` and may later read the
    // file. To support this edge case, we first move the file to a temp file and point
    // target file location to the new temp file. `unref()` should only ever be called once.
    #[inline]
    async fn unref(&self) {
        {
            let mut encoded_file_path = self.encoded_file_path.write().await;
            if encoded_file_path.path_type == PathType::Temp {
                // We are already a temp file that is now marked for deletion on drop.
                // This is very rare, but most likely the rename into the content path failed.
                return;
            }
            let from_path = encoded_file_path.get_file_path();
            let new_key = make_temp_key(&encoded_file_path.key);

            let to_path =
                to_full_path_from_key(&encoded_file_path.shared_context.temp_path, &new_key);

            if let Err(err) = fs::rename(&from_path, &to_path).await {
                event!(
                    Level::WARN,
                    key = ?encoded_file_path.key,
                    ?from_path,
                    ?to_path,
                    ?err,
                    "Failed to rename file",
                );
            } else {
                event!(
                    Level::INFO,
                    key = ?encoded_file_path.key,
                    ?from_path,
                    ?to_path,
                    "Renamed file",
                );
                encoded_file_path.path_type = PathType::Temp;
                encoded_file_path.key = new_key;
            }
        }
    }
}

#[inline]
fn digest_from_filename(file_name: &str) -> Result<DigestInfo, Error> {
    let (hash, size) = file_name.split_once('-').err_tip(|| "")?;
    let size = size.parse::<i64>()?;
    DigestInfo::try_new(hash, size)
}

pub fn key_from_file(file_name: &str, file_type: FileType) -> Result<StoreKey<'_>, Error> {
    match file_type {
        FileType::String => Ok(StoreKey::new_str(file_name)),
        FileType::Digest => digest_from_filename(file_name).map(StoreKey::Digest),
    }
}

/// The number of files to read the metadata for at the same time when running
/// `add_files_to_cache`.
const SIMULTANEOUS_METADATA_READS: usize = 200;

async fn add_files_to_cache<Fe: FileEntry>(
    evicting_map: &EvictingMap<StoreKeyBorrow, Arc<Fe>, SystemTime>,
    anchor_time: &SystemTime,
    shared_context: &Arc<SharedContext>,
    block_size: u64,
    rename_fn: fn(&OsStr, &OsStr) -> Result<(), std::io::Error>,
) -> Result<(), Error> {
    #[expect(clippy::too_many_arguments)]
    async fn process_entry<Fe: FileEntry>(
        evicting_map: &EvictingMap<StoreKeyBorrow, Arc<Fe>, SystemTime>,
        file_name: &str,
        file_type: FileType,
        atime: SystemTime,
        data_size: u64,
        block_size: u64,
        anchor_time: &SystemTime,
        shared_context: &Arc<SharedContext>,
    ) -> Result<(), Error> {
        let key = key_from_file(file_name, file_type)?;

        let file_entry = Fe::create(
            data_size,
            block_size,
            RwLock::new(EncodedFilePath {
                shared_context: shared_context.clone(),
                path_type: PathType::Content,
                key: key.borrow().into_owned(),
            }),
        );
        let time_since_anchor = anchor_time
            .duration_since(atime)
            .map_err(|_| make_input_err!("File access time newer than now"))?;
        evicting_map
            .insert_with_time(
                key.into_owned().into(),
                Arc::new(file_entry),
                time_since_anchor.as_secs() as i32,
            )
            .await;
        Ok(())
    }

    async fn read_files(
        folder: Option<&str>,
        shared_context: &SharedContext,
    ) -> Result<Vec<(String, SystemTime, u64, bool)>, Error> {
        // Note: In Dec 2024 this is for backwards compatibility with the old
        // way files were stored on disk. Previously all files were in a single
        // folder regardless of the StoreKey type. This allows old versions of
        // nativelink file layout to be upgraded at startup time.
        // This logic can be removed once more time has passed.
        let read_dir = if let Some(folder) = folder {
            format!("{}/{folder}/", shared_context.content_path)
        } else {
            format!("{}/", shared_context.content_path)
        };
        let (_permit, dir_handle) = fs::read_dir(read_dir)
            .await
            .err_tip(|| "Failed opening content directory for iterating in filesystem store")?
            .into_inner();

        let read_dir_stream = ReadDirStream::new(dir_handle);
        read_dir_stream
            .map(|dir_entry| async move {
                let dir_entry = dir_entry.unwrap();
                let file_name = dir_entry.file_name().into_string().unwrap();
                let metadata = dir_entry
                    .metadata()
                    .await
                    .err_tip(|| "Failed to get metadata in filesystem store")?;
                // We need to filter out folders - we do not want to try to cache the s and d folders.
                let is_file =
                    metadata.is_file() || !(file_name == STR_FOLDER || file_name == DIGEST_FOLDER);
                let atime = match metadata.accessed() {
                    Ok(atime) => atime,
                    Err(err) => {
                        panic!(
                            "{}{}{} : {} {:?}",
                            "It appears this filesystem does not support access time. ",
                            "Please configure this program to run on a drive that supports ",
                            "atime",
                            file_name,
                            err
                        );
                    }
                };
                Result::<(String, SystemTime, u64, bool), Error>::Ok((
                    file_name,
                    atime,
                    metadata.len(),
                    is_file,
                ))
            })
            .buffer_unordered(SIMULTANEOUS_METADATA_READS)
            .try_collect()
            .await
    }

    /// Note: In Dec 2024 this is for backwards compatibility with the old
    /// way files were stored on disk. Previously all files were in a single
    /// folder regardless of the [`StoreKey`] type. This moves files from the old cache
    /// location to the new cache location, under [`DIGEST_FOLDER`].
    async fn move_old_cache(
        shared_context: &Arc<SharedContext>,
        rename_fn: fn(&OsStr, &OsStr) -> Result<(), std::io::Error>,
    ) -> Result<(), Error> {
        let file_infos = read_files(None, shared_context).await?;

        let from_path = shared_context.content_path.to_string();

        let to_path = format!("{}/{DIGEST_FOLDER}", shared_context.content_path);

        for (file_name, _, _, _) in file_infos.into_iter().filter(|x| x.3) {
            let from_file: OsString = format!("{from_path}/{file_name}").into();
            let to_file: OsString = format!("{to_path}/{file_name}").into();

            if let Err(err) = rename_fn(&from_file, &to_file) {
                event!(
                    Level::WARN,
                    ?from_file,
                    ?to_file,
                    ?err,
                    "Failed to rename file",
                );
            } else {
                event!(Level::INFO, ?from_file, ?to_file, "Renamed file",);
            }
        }
        Ok(())
    }

    async fn add_files_to_cache<Fe: FileEntry>(
        evicting_map: &EvictingMap<StoreKeyBorrow, Arc<Fe>, SystemTime>,
        anchor_time: &SystemTime,
        shared_context: &Arc<SharedContext>,
        block_size: u64,
        folder: &str,
    ) -> Result<(), Error> {
        let file_infos = read_files(Some(folder), shared_context).await?;
        let file_type = match folder {
            STR_FOLDER => FileType::String,
            DIGEST_FOLDER => FileType::Digest,
            _ => panic!("Invalid folder type"),
        };

        let path_root = format!("{}/{folder}", shared_context.content_path);

        for (file_name, atime, data_size, _) in file_infos.into_iter().filter(|x| x.3) {
            let result = process_entry(
                evicting_map,
                &file_name,
                file_type,
                atime,
                data_size,
                block_size,
                anchor_time,
                shared_context,
            )
            .await;
            if let Err(err) = result {
                event!(
                    Level::WARN,
                    ?file_name,
                    ?err,
                    "Failed to add file to eviction cache",
                );
                // Ignore result.
                let _ = fs::remove_file(format!("{path_root}/{file_name}")).await;
            }
        }
        Ok(())
    }

    move_old_cache(shared_context, rename_fn).await?;

    add_files_to_cache(
        evicting_map,
        anchor_time,
        shared_context,
        block_size,
        DIGEST_FOLDER,
    )
    .await?;

    add_files_to_cache(
        evicting_map,
        anchor_time,
        shared_context,
        block_size,
        STR_FOLDER,
    )
    .await?;
    Ok(())
}

async fn prune_temp_path(temp_path: &str) -> Result<(), Error> {
    async fn prune_temp_inner(temp_path: &str, subpath: &str) -> Result<(), Error> {
        let (_permit, dir_handle) = fs::read_dir(format!("{temp_path}/{subpath}"))
            .await
            .err_tip(|| {
                "Failed opening temp directory to prune partial downloads in filesystem store"
            })?
            .into_inner();

        let mut read_dir_stream = ReadDirStream::new(dir_handle);
        while let Some(dir_entry) = read_dir_stream.next().await {
            let path = dir_entry?.path();
            if let Err(err) = fs::remove_file(&path).await {
                event!(Level::WARN, ?path, ?err, "Failed to delete file",);
            }
        }
        Ok(())
    }

    prune_temp_inner(temp_path, STR_FOLDER).await?;
    prune_temp_inner(temp_path, DIGEST_FOLDER).await?;
    Ok(())
}

#[derive(MetricsComponent)]
pub struct FilesystemStore<Fe: FileEntry = FileEntryImpl> {
    #[metric]
    shared_context: Arc<SharedContext>,
    #[metric(group = "evicting_map")]
    evicting_map: Arc<EvictingMap<StoreKeyBorrow, Arc<Fe>, SystemTime>>,
    #[metric(help = "Block size of the configured filesystem")]
    block_size: u64,
    #[metric(help = "Size of the configured read buffer size")]
    read_buffer_size: usize,
    weak_self: Weak<Self>,
    sleep_fn: fn(Duration) -> Sleep,
    rename_fn: fn(&OsStr, &OsStr) -> Result<(), std::io::Error>,
}

impl<Fe: FileEntry> FilesystemStore<Fe> {
    pub async fn new(spec: &FilesystemSpec) -> Result<Arc<Self>, Error> {
        Self::new_with_timeout_and_rename_fn(spec, sleep, |from, to| std::fs::rename(from, to))
            .await
    }

    pub async fn new_with_timeout_and_rename_fn(
        spec: &FilesystemSpec,
        sleep_fn: fn(Duration) -> Sleep,
        rename_fn: fn(&OsStr, &OsStr) -> Result<(), std::io::Error>,
    ) -> Result<Arc<Self>, Error> {
        async fn create_subdirs(path: &str) -> Result<(), Error> {
            fs::create_dir_all(format!("{path}/{STR_FOLDER}"))
                .await
                .err_tip(|| format!("Failed to create directory {path}/{STR_FOLDER}"))?;
            fs::create_dir_all(format!("{path}/{DIGEST_FOLDER}"))
                .await
                .err_tip(|| format!("Failed to create directory {path}/{DIGEST_FOLDER}"))
        }

        let now = SystemTime::now();

        let empty_policy = nativelink_config::stores::EvictionPolicy::default();
        let eviction_policy = spec.eviction_policy.as_ref().unwrap_or(&empty_policy);
        let evicting_map = Arc::new(EvictingMap::new(eviction_policy, now));

        // Create temp and content directories and the s and d subdirectories.

        create_subdirs(&spec.temp_path).await?;
        create_subdirs(&spec.content_path).await?;

        let shared_context = Arc::new(SharedContext {
            active_drop_spawns: AtomicU64::new(0),
            temp_path: spec.temp_path.clone(),
            content_path: spec.content_path.clone(),
        });

        let block_size = if spec.block_size == 0 {
            DEFAULT_BLOCK_SIZE
        } else {
            spec.block_size
        };
        add_files_to_cache(
            evicting_map.as_ref(),
            &now,
            &shared_context,
            block_size,
            rename_fn,
        )
        .await?;
        prune_temp_path(&shared_context.temp_path).await?;

        let read_buffer_size = if spec.read_buffer_size == 0 {
            DEFAULT_BUFF_SIZE
        } else {
            spec.read_buffer_size as usize
        };
        Ok(Arc::new_cyclic(|weak_self| Self {
            shared_context,
            evicting_map,
            block_size,
            read_buffer_size,
            weak_self: weak_self.clone(),
            sleep_fn,
            rename_fn,
        }))
    }

    pub fn get_arc(&self) -> Option<Arc<Self>> {
        self.weak_self.upgrade()
    }

    pub async fn get_file_entry_for_digest(&self, digest: &DigestInfo) -> Result<Arc<Fe>, Error> {
        self.evicting_map
            .get::<StoreKey<'static>>(&digest.into())
            .await
            .ok_or_else(|| make_err!(Code::NotFound, "{digest} not found in filesystem store"))
    }

    async fn update_file<'a>(
        self: Pin<&'a Self>,
        mut entry: Fe,
        mut resumeable_temp_file: fs::ResumeableFileSlot,
        final_key: StoreKey<'static>,
        mut reader: DropCloserReadHalf,
    ) -> Result<(), Error> {
        let mut data_size = 0;
        loop {
            let Ok(data_result) = timeout(fs::idle_file_descriptor_timeout(), reader.recv()).await
            else {
                // In the event we timeout, we want to close the writing file, to prevent
                // the file descriptor left open for long periods of time.
                // This is needed because we wrap `fs` so only a fixed number of file
                // descriptors may be open at any given time. If we are streaming from
                // File -> File, it can cause a deadlock if the Write file is not sending
                // data because it is waiting for a file descriotor to open before sending data.
                resumeable_temp_file.close_file().await.err_tip(|| {
                    "Could not close file due to timeout in FileSystemStore::update_file"
                })?;
                continue;
            };
            let mut data = data_result.err_tip(|| "Failed to receive data in filesystem store")?;
            let data_len = data.len();
            if data_len == 0 {
                break; // EOF.
            }
            resumeable_temp_file
                .as_writer()
                .await
                .err_tip(|| "in filesystem_store::update_file")?
                .write_all_buf(&mut data)
                .await
                .err_tip(|| "Failed to write data into filesystem store")?;
            data_size += data_len as u64;
        }

        resumeable_temp_file
            .as_writer()
            .await
            .err_tip(|| "in filesystem_store::update_file")?
            .as_ref()
            .sync_all()
            .await
            .err_tip(|| "Failed to sync_data in filesystem store")?;

        drop(resumeable_temp_file);

        *entry.data_size_mut() = data_size;
        self.emplace_file(final_key, Arc::new(entry)).await
    }

    async fn emplace_file(&self, key: StoreKey<'static>, entry: Arc<Fe>) -> Result<(), Error> {
        // This sequence of events is quite ticky to understand due to the amount of triggers that
        // happen, async'ness of it and the locking. So here is a breakdown of what happens:
        // 1. Here will hold a write lock on any file operations of this FileEntry.
        // 2. Then insert the entry into the evicting map. This may trigger an eviction of other
        //    entries.
        // 3. Eviction triggers `unref()`, which grabs a write lock on the evicted FileEntrys
        //    during the rename.
        // 4. It should be impossible for items to be added while eviction is happening, so there
        //    should not be a deadlock possability. However, it is possible for the new FileEntry
        //    to be evicted before the file is moved into place. Eviction of the newly inserted
        //    item is not possible within the `insert()` call because the write lock inside the
        //    eviction map. If an eviction of new item happens after `insert()` but before
        //    `rename()` then we get to finish our operation because the `unref()` of the new item
        //    will be blocked on us because we currently have the lock.
        // 5. Move the file into place. Since we hold a write lock still anyone that gets our new
        //    FileEntry (which has not yet been placed on disk) will not be able to read the file's
        //    contents until we relese the lock.
        let evicting_map = self.evicting_map.clone();
        let rename_fn = self.rename_fn;

        // We need to guarantee that this will get to the end even if the parent future is dropped.
        // See: https://github.com/TraceMachina/nativelink/issues/495
        background_spawn!("filesystem_store_emplace_file", async move {
            let mut encoded_file_path = entry.get_encoded_file_path().write().await;
            let final_path = get_file_path_raw(
                &PathType::Content,
                encoded_file_path.shared_context.as_ref(),
                &key,
            );

            evicting_map
                .insert(key.borrow().into_owned().into(), entry.clone())
                .await;

            let from_path = encoded_file_path.get_file_path();
            // Internally tokio spawns fs commands onto a blocking thread anyways.
            // Since we are already on a blocking thread, we just need the `fs` wrapper to manage
            // an open-file permit (ensure we don't open too many files at once).
            let result = (rename_fn)(&from_path, &final_path)
                .err_tip(|| format!("Failed to rename temp file to final path {final_path:?}"));

            // In the event our move from temp file to final file fails we need to ensure we remove
            // the entry from our map.
            // Remember: At this point it is possible for another thread to have a reference to
            // `entry`, so we can't delete the file, only drop() should ever delete files.
            if let Err(err) = result {
                event!(
                    Level::ERROR,
                    ?err,
                    ?from_path,
                    ?final_path,
                    "Failed to rename file",
                );
                // Warning: To prevent deadlock we need to release our lock or during `remove_if()`
                // it will call `unref()`, which triggers a write-lock on `encoded_file_path`.
                drop(encoded_file_path);
                // It is possible that the item in our map is no longer the item we inserted,
                // So, we need to conditionally remove it only if the pointers are the same.

                evicting_map
                    .remove_if(&key, |map_entry| Arc::<Fe>::ptr_eq(map_entry, &entry))
                    .await;
                return Err(err);
            }
            encoded_file_path.path_type = PathType::Content;
            encoded_file_path.key = key;
            Ok(())
        })
        .await
        .err_tip(|| "Failed to create spawn in filesystem store update_file")?
    }
}

#[async_trait]
impl<Fe: FileEntry> StoreDriver for FilesystemStore<Fe> {
    async fn has_with_results(
        self: Pin<&Self>,
        keys: &[StoreKey<'_>],
        results: &mut [Option<u64>],
    ) -> Result<(), Error> {
        self.evicting_map
            .sizes_for_keys::<_, StoreKey<'_>, &StoreKey<'_>>(
                keys.iter(),
                results,
                false, /* peek */
            )
            .await;
        // We need to do a special pass to ensure our zero files exist.
        // If our results failed and the result was a zero file, we need to
        // create the file by spec.
        for (key, result) in keys.iter().zip(results.iter_mut()) {
            if result.is_some() || !is_zero_digest(key.borrow()) {
                continue;
            }
            let (mut tx, rx) = make_buf_channel_pair();
            let send_eof_result = tx.send_eof();
            self.update(key.borrow(), rx, UploadSizeInfo::ExactSize(0))
                .await
                .err_tip(|| format!("Failed to create zero file for key {}", key.as_str()))
                .merge(
                    send_eof_result
                        .err_tip(|| "Failed to send zero file EOF in filesystem store has"),
                )?;

            *result = Some(0);
        }
        Ok(())
    }

    async fn update(
        self: Pin<&Self>,
        key: StoreKey<'_>,
        reader: DropCloserReadHalf,
        _upload_size: UploadSizeInfo,
    ) -> Result<(), Error> {
        let temp_key = make_temp_key(&key);
        let (entry, temp_file, temp_full_path) = Fe::make_and_open_file(
            self.block_size,
            EncodedFilePath {
                shared_context: self.shared_context.clone(),
                path_type: PathType::Temp,
                key: temp_key,
            },
        )
        .await?;

        self.update_file(entry, temp_file, key.into_owned(), reader)
            .await
            .err_tip(|| format!("While processing with temp file {temp_full_path:?}"))
    }

    fn optimized_for(&self, optimization: StoreOptimizations) -> bool {
        optimization == StoreOptimizations::FileUpdates
    }

    async fn update_with_whole_file(
        self: Pin<&Self>,
        key: StoreKey<'_>,
        mut file: fs::ResumeableFileSlot,
        upload_size: UploadSizeInfo,
    ) -> Result<Option<fs::ResumeableFileSlot>, Error> {
        let path = file.get_path().as_os_str().to_os_string();
        let file_size = match upload_size {
            UploadSizeInfo::ExactSize(size) => size,
            UploadSizeInfo::MaxSize(_) => file
                .as_reader()
                .await
                .err_tip(|| {
                    format!("While getting metadata for {path:?} in update_with_whole_file")
                })?
                .get_ref()
                .as_ref()
                .metadata()
                .await
                .err_tip(|| format!("While reading metadata for {path:?}"))?
                .len(),
        };
        let entry = Fe::create(
            file_size,
            self.block_size,
            RwLock::new(EncodedFilePath {
                shared_context: self.shared_context.clone(),
                path_type: PathType::Custom(path),
                key: key.borrow().into_owned(),
            }),
        );
        // We are done with the file, if we hold a reference to the file here, it could
        // result in a deadlock if `emplace_file()` also needs file descriptors.
        drop(file);
        self.emplace_file(key.into_owned(), Arc::new(entry))
            .await
            .err_tip(|| "Could not move file into store in upload_file_to_store, maybe dest is on different volume?")?;
        return Ok(None);
    }

    async fn get_part(
        self: Pin<&Self>,
        key: StoreKey<'_>,
        writer: &mut DropCloserWriteHalf,
        offset: u64,
        length: Option<u64>,
    ) -> Result<(), Error> {
        if is_zero_digest(key.borrow()) {
            self.has(key.borrow())
                .await
                .err_tip(|| "Failed to check if zero digest exists in filesystem store")?;
            writer
                .send_eof()
                .err_tip(|| "Failed to send zero EOF in filesystem store get_part")?;
            return Ok(());
        }

        let entry = self.evicting_map.get(&key).await.ok_or_else(|| {
            make_err!(
                Code::NotFound,
                "{} not found in filesystem store here",
                key.as_str()
            )
        })?;
        let read_limit = length.unwrap_or(u64::MAX);
        let mut resumeable_temp_file = entry.read_file_part(offset, read_limit).await?;

        loop {
            let mut buf = BytesMut::with_capacity(self.read_buffer_size);
            resumeable_temp_file
                .as_reader()
                .await
                .err_tip(|| "In FileSystemStore::get_part()")?
                .read_buf(&mut buf)
                .await
                .err_tip(|| "Failed to read data in filesystem store")?;
            if buf.is_empty() {
                break; // EOF.
            }
            // In the event it takes a while to send the data to the client, we want to close the
            // reading file, to prevent the file descriptor left open for long periods of time.
            // Failing to do so might cause deadlocks if the receiver is unable to receive data
            // because it is waiting for a file descriptor to open before receiving data.
            // Using `ResumeableFileSlot` will re-open the file in the event it gets closed on the
            // next iteration.
            let buf_content = buf.freeze();
            loop {
                let sleep_fn = (self.sleep_fn)(fs::idle_file_descriptor_timeout());
                tokio::pin!(sleep_fn);
                tokio::select! {
                    () = & mut (sleep_fn) => {
                        resumeable_temp_file
                            .close_file()
                            .await
                            .err_tip(|| "Could not close file due to timeout in FileSystemStore::get_part")?;
                    }
                    res = writer.send(buf_content.clone()) => {
                        match res {
                            Ok(()) => break,
                            Err(err) => {
                                return Err(err).err_tip(|| "Failed to send chunk in filesystem store get_part");
                            }
                        }
                    }
                }
            }
        }
        writer
            .send_eof()
            .err_tip(|| "Filed to send EOF in filesystem store get_part")?;

        Ok(())
    }

    fn inner_store(&self, _digest: Option<StoreKey>) -> &dyn StoreDriver {
        self
    }

    fn as_any<'a>(&'a self) -> &'a (dyn std::any::Any + Sync + Send + 'static) {
        self
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Sync + Send + 'static> {
        self
    }

    fn register_health(self: Arc<Self>, registry: &mut HealthRegistryBuilder) {
        registry.register_indicator(self);
    }
}

#[async_trait]
impl<Fe: FileEntry> HealthStatusIndicator for FilesystemStore<Fe> {
    fn get_name(&self) -> &'static str {
        "FilesystemStore"
    }

    async fn check_health(&self, namespace: Cow<'static, str>) -> HealthStatus {
        StoreDriver::check_health(Pin::new(self), namespace).await
    }
}
