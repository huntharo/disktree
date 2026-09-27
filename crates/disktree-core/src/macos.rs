//! Directory metadata in batches, through Darwin's `getattrlistbulk(2)`.
//!
//! Unsafe code is limited to the system call and its aligned buffer view.
//! Packed records use checked slices; missing attributes use no-follow stat.

#![allow(
    unsafe_code,
    reason = "Darwin's bulk directory call has no std wrapper; the call documents its safety"
)]

use std::cell::OnceCell;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// A batch holds hundreds of records without retaining a whole directory.
const BUFFER_BYTES: usize = 64 * 1024;
// Darwin sys/attr.h and sys/stat.h constants absent from libc.
const ATTR_CMN_ERROR: u32 = 0x2000_0000;
const SF_FIRMLINK: u32 = 0x0080_0000;
const COMMON: u32 = libc::ATTR_CMN_RETURNED_ATTRS
    | ATTR_CMN_ERROR
    | libc::ATTR_CMN_NAME
    | libc::ATTR_CMN_DEVID
    | libc::ATTR_CMN_OBJTYPE
    | libc::ATTR_CMN_MODTIME
    | libc::ATTR_CMN_FLAGS
    | libc::ATTR_CMN_FILEID;
const FILE: u32 = libc::ATTR_FILE_LINKCOUNT
    | libc::ATTR_FILE_ALLOCSIZE
    | libc::ATTR_FILE_DATALENGTH;
// Length followed by the five returned attribute bitmaps.
const HEADER_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    Other,
}

impl Kind {
    fn of(kind: fs::FileType) -> Self {
        if kind.is_dir() {
            Self::Directory
        } else if kind.is_file() {
            Self::File
        } else if kind.is_symlink() {
            Self::Symlink
        } else {
            Self::Other
        }
    }
}

#[derive(Debug)]
pub struct Metadata {
    pub apparent: u64,
    pub allocated: u64,
    pub device: u64,
    pub inode: u64,
    pub modified: i64,
    pub links: u64,
}

impl Metadata {
    fn of(meta: &fs::Metadata) -> Self {
        Self {
            apparent: meta.len(),
            allocated: meta.blocks().saturating_mul(512),
            device: meta.dev(),
            inode: meta.ino(),
            modified: meta
                .modified()
                .ok()
                .and_then(|time| {
                    time.duration_since(std::time::UNIX_EPOCH).ok()
                })
                .map_or(0, |since| {
                    i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
                }),
            links: meta.nlink(),
        }
    }
}

#[derive(Debug)]
pub struct Entry {
    pub file_name: OsString,
    pub kind: Kind,
    pub metadata: OnceCell<io::Result<Metadata>>,
    parent: Arc<Path>,
}

impl Entry {
    pub fn path(&self) -> PathBuf {
        self.parent.join(&self.file_name)
    }

    pub fn metadata(&self) -> Result<&Metadata, &io::Error> {
        self.metadata
            .get_or_init(|| {
                fs::symlink_metadata(self.path())
                    .map(|meta| Metadata::of(&meta))
            })
            .as_ref()
    }
}

// Darwin requires each record to start at an eight-byte-aligned address.
#[derive(Debug)]
struct Buffer(Box<[u64]>);

impl Buffer {
    fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: all words are initialized, every bit pattern is valid for
        // u64, and u8 needs no alignment. This exclusive byte view covers
        // exactly the allocation and cannot outlive its mutable borrow.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.0.as_mut_ptr().cast(),
                size_of_val(&*self.0),
            )
        }
    }
}

#[derive(Debug)]
pub struct ReadDir {
    directory: File,
    parent: Arc<Path>,
    buffer: Buffer,
    offset: usize,
    remaining: usize,
    started: bool,
    done: bool,
    fallback: Option<fs::ReadDir>,
}

pub fn read_dir(path: &Path) -> io::Result<ReadDir> {
    Ok(ReadDir {
        directory: OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(path)?,
        parent: Arc::from(path),
        buffer: Buffer(
            vec![0; BUFFER_BYTES / size_of::<u64>()].into_boxed_slice(),
        ),
        offset: 0,
        remaining: 0,
        started: false,
        done: false,
        fallback: None,
    })
}

impl ReadDir {
    fn refill(&mut self) -> io::Result<()> {
        loop {
            let mut attributes = libc::attrlist {
                bitmapcount: libc::ATTR_BIT_MAP_COUNT,
                reserved: 0,
                commonattr: COMMON,
                volattr: 0,
                dirattr: 0,
                fileattr: FILE,
                forkattr: 0,
            };
            // SAFETY: the File owns an open directory descriptor; attrlist
            // is initialized; the aligned buffer is exclusively writable
            // for exactly BUFFER_BYTES. No pointers escape this call.
            let count = unsafe {
                libc::getattrlistbulk(
                    self.directory.as_raw_fd(),
                    (&raw mut attributes).cast(),
                    self.buffer.bytes().as_mut_ptr().cast(),
                    BUFFER_BYTES,
                    0,
                )
            };
            if count >= 0 {
                self.remaining = usize::try_from(count)
                    .map_err(|_| invalid("invalid directory record count"))?;
                self.offset = 0;
                self.done = count == 0;
                self.started |= count > 0;
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return self.refill_error(error);
        }
    }

    fn refill_error(&mut self, error: io::Error) -> io::Result<()> {
        // A readable directory may deny metadata/search access. Let std
        // enumerate its names and surface per-entry errors. Unsupported
        // filesystems also retain the ordinary walk. Never restart after
        // emitting entries: doing so could duplicate part of the tree.
        if !self.started
            && matches!(
                error.raw_os_error(),
                Some(libc::EACCES | libc::ENOTSUP | libc::ENOSYS)
            )
        {
            self.fallback = Some(fs::read_dir(&self.parent)?);
            Ok(())
        } else {
            Err(error)
        }
    }

    fn next_record(&mut self) -> io::Result<Entry> {
        let remaining =
            self.buffer.bytes().get(self.offset..).ok_or_else(|| {
                invalid("directory record offset exceeds buffer")
            })?;
        let length = u32::from_ne_bytes(Cursor::new(remaining).take()?);
        let length = usize::try_from(length).map_err(|_| {
            invalid("directory record length exceeds address space")
        })?;
        if length < HEADER_BYTES || length % 8 != 0 {
            return Err(invalid("invalid directory record length"));
        }
        let bytes = remaining
            .get(..length)
            .ok_or_else(|| invalid("directory record exceeds buffer"))?;
        let record = Record::parse(bytes)?;
        self.offset += length;
        self.remaining -= 1;
        Ok(record.entry(Arc::clone(&self.parent)))
    }

    fn standard_entry(&self, entry: &fs::DirEntry) -> io::Result<Entry> {
        let kind = Kind::of(entry.file_type()?);
        let metadata = if matches!(kind, Kind::Directory | Kind::Symlink) {
            OnceCell::new()
        } else {
            OnceCell::from(entry.metadata().map(|meta| Metadata::of(&meta)))
        };
        Ok(Entry {
            file_name: entry.file_name(),
            kind,
            metadata,
            parent: Arc::clone(&self.parent),
        })
    }
}

impl Iterator for ReadDir {
    type Item = io::Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            if let Some(fallback) = &mut self.fallback {
                return fallback.next().map(|entry| {
                    entry.and_then(|entry| self.standard_entry(&entry))
                });
            }
            if self.remaining == 0 {
                if let Err(error) = self.refill() {
                    self.done = true;
                    return Some(Err(error));
                }
                continue;
            }
            match self.next_record() {
                Ok(entry)
                    if entry.file_name == "." || entry.file_name == ".." => {}
                Ok(entry) => return Some(Ok(entry)),
                Err(error) => {
                    self.done = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

#[derive(Debug)]
struct Record {
    name: OsString,
    kind: Kind,
    error: i32,
    flags: Option<u32>,
    metadata: Option<Metadata>,
}

impl Record {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(bytes);
        cursor.take::<4>()?;
        let common = u32::from_ne_bytes(cursor.take()?);
        let volume = u32::from_ne_bytes(cursor.take()?);
        let directory = u32::from_ne_bytes(cursor.take()?);
        let file = u32::from_ne_bytes(cursor.take()?);
        let fork = u32::from_ne_bytes(cursor.take()?);
        if common & libc::ATTR_CMN_RETURNED_ATTRS == 0
            || common & !COMMON != 0
            || file & !FILE != 0
            || volume != 0
            || directory != 0
            || fork != 0
        {
            return Err(invalid("unexpected returned directory attributes"));
        }
        // ATTR_CMN_ERROR precedes all other common fields, regardless of
        // its bit position. Without PACK_INVAL_ATTRS, missing fields occupy
        // no bytes; every read follows the returned bitmap.
        let error = cursor
            .attribute(common, ATTR_CMN_ERROR)?
            .map_or(0, i32::from_ne_bytes);
        let name = cursor.name(common)?;
        let device = cursor
            .attribute(common, libc::ATTR_CMN_DEVID)?
            .map(|raw| i64::from(i32::from_ne_bytes(raw)).cast_unsigned());
        let kind = match cursor
            .attribute(common, libc::ATTR_CMN_OBJTYPE)?
            .map(u32::from_ne_bytes)
        {
            // Darwin's enum vtype, from sys/vnode.h.
            Some(1) => Kind::File,
            Some(2) => Kind::Directory,
            Some(5) => Kind::Symlink,
            _ => Kind::Other,
        };
        let modified = cursor
            .attribute::<16>(common, libc::ATTR_CMN_MODTIME)?
            .map(modified_seconds)
            .transpose()?;
        let flags = cursor
            .attribute(common, libc::ATTR_CMN_FLAGS)?
            .map(u32::from_ne_bytes);
        let inode = cursor
            .attribute(common, libc::ATTR_CMN_FILEID)?
            .map(u64::from_ne_bytes);
        let links = cursor
            .attribute(file, libc::ATTR_FILE_LINKCOUNT)?
            .map(|raw| u64::from(u32::from_ne_bytes(raw)));
        let allocated = cursor
            .attribute(file, libc::ATTR_FILE_ALLOCSIZE)?
            .map(u64::from_ne_bytes);
        let apparent = cursor
            .attribute(file, libc::ATTR_FILE_DATALENGTH)?
            .map(u64::from_ne_bytes);
        let metadata =
            match (device, inode, modified, links, allocated, apparent) {
                (
                    Some(device),
                    Some(inode),
                    Some(modified),
                    Some(links),
                    Some(allocated),
                    Some(apparent),
                ) => {
                    Some(Metadata {
                        device,
                        inode,
                        modified,
                        links,
                        // Total allocation includes resource forks. Match the
                        // 512-byte stat accounting unit, rounding up as FTS does.
                        allocated: allocated.div_ceil(512).saturating_mul(512),
                        apparent,
                    })
                }
                _ => None,
            };
        Ok(Self {
            name,
            kind,
            error,
            flags,
            metadata,
        })
    }

    fn entry(self, parent: Arc<Path>) -> Entry {
        let mut kind = self.kind;
        let metadata = if self.error != 0 {
            OnceCell::from(Err(io::Error::from_raw_os_error(self.error)))
        } else if matches!(kind, Kind::Directory | Kind::Symlink)
            && self.flags.is_some_and(|flags| flags & SF_FIRMLINK == 0)
        {
            // The scanner stats directories immediately before descent and
            // links when deciding whether to follow them. Fetching their
            // metadata here would repeat that work for every such entry.
            OnceCell::new()
        } else if kind == Kind::File
            && self.flags.is_some_and(|flags| flags & SF_FIRMLINK == 0)
            && let Some(metadata) = self.metadata
        {
            OnceCell::from(Ok(metadata))
        } else {
            // Bulk metadata describes underlying mount/firmlink entries.
            // A path lookup sees the visible directory; it also supplies
            // missing attributes and metadata for special file types.
            OnceCell::from(fs::symlink_metadata(parent.join(&self.name)).map(
                |meta| {
                    kind = Kind::of(meta.file_type());
                    Metadata::of(&meta)
                },
            ))
        };
        Entry {
            file_name: self.name,
            kind,
            metadata,
            parent,
        }
    }
}

fn modified_seconds(raw: [u8; 16]) -> io::Result<i64> {
    let seconds = i64::from_ne_bytes(raw[..8].try_into().expect("eight bytes"));
    let nanos = i64::from_ne_bytes(raw[8..].try_into().expect("eight bytes"));
    if !(-1_000_000_000..1_000_000_000).contains(&nanos) {
        return Err(invalid("invalid modification time"));
    }
    // Rust's existing scan maps every pre-epoch timestamp to zero. Darwin
    // can represent the fractional part before the epoch with negative ns.
    Ok(if seconds < 0 || (seconds == 0 && nanos < 0) {
        0
    } else if nanos < 0 {
        seconds - 1
    } else {
        seconds
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let value = self
            .bytes
            .get(self.offset..)
            .and_then(|bytes| bytes.first_chunk::<N>())
            .ok_or_else(|| invalid("attribute exceeds directory record"))?;
        self.offset += N;
        Ok(*value)
    }

    fn attribute<const N: usize>(
        &mut self,
        mask: u32,
        bit: u32,
    ) -> io::Result<Option<[u8; N]>> {
        if mask & bit == 0 {
            Ok(None)
        } else {
            self.take().map(Some)
        }
    }

    fn name(&mut self, common: u32) -> io::Result<OsString> {
        if common & libc::ATTR_CMN_NAME == 0 {
            return Err(invalid("directory record has no name"));
        }
        let reference = self.offset;
        let relative = i32::from_ne_bytes(self.take()?);
        let length = u32::from_ne_bytes(self.take()?);
        let start = isize::try_from(relative)
            .ok()
            .and_then(|relative| reference.checked_add_signed(relative));
        let name = start
            .and_then(|start| {
                usize::try_from(length)
                    .ok()
                    .and_then(|length| start.checked_add(length))
                    .and_then(|end| self.bytes.get(start..end))
            })
            .ok_or_else(|| invalid("filename exceeds directory record"))?;
        let name = name
            .strip_suffix(&[0])
            .filter(|name| {
                !name.is_empty() && !name.contains(&0) && !name.contains(&b'/')
            })
            .ok_or_else(|| invalid("invalid directory entry name"))?;
        Ok(OsString::from_vec(name.to_vec()))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "macos/tests.rs"]
mod tests;
