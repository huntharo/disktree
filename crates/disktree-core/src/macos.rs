//! Darwin bulk clone hints and conditional private-size reads.
//!
//! Attribute records are packed on four-byte boundaries: decode bytes,
//! never overlay Rust structs. The only unsafe operations are OS calls.
#![allow(unsafe_code, reason = "Darwin attribute APIs have no safe wrapper")]

use std::ffi::{CString, OsString};
use std::fs::{self, File, Metadata};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::sharing::CloneInfo;

// <sys/attr.h> and <sys/stat.h>; libc omits CLONE_REFCNT.
const REFCNT: u32 = 0x1000;
const MAY_SHARE: u64 = 0x1 | 0x40;
const EXTENDED: u32 = libc::FSOPT_ATTR_CMN_EXTENDED;
const RETURNED: u32 = libc::ATTR_CMN_RETURNED_ATTRS;
const HINTS: u32 = libc::ATTR_CMNEXT_CLONEID | libc::ATTR_CMNEXT_EXT_FLAGS;

pub struct Entry {
    path: PathBuf,
    name: OsString,
    hints: Option<(u64, u64)>,
    metadata: OnceLock<io::Result<Metadata>>,
}

impl Entry {
    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }
    pub fn file_name(&self) -> OsString {
        self.name.clone()
    }
    pub fn metadata(&self) -> io::Result<Metadata> {
        self.metadata
            .get_or_init(|| fs::symlink_metadata(&self.path))
            .as_ref()
            .cloned()
            .map_err(|error| io::Error::new(error.kind(), error.to_string()))
    }
    pub fn file_type(&self) -> io::Result<fs::FileType> {
        self.metadata().map(|meta| meta.file_type())
    }
    pub fn clone_info(&self, meta: &Metadata) -> Option<Box<CloneInfo>> {
        let (id, flags) = self.hints?;
        if !meta.is_file() || flags & MAY_SHARE == 0 {
            return None;
        }
        Some(Box::new(private_info(&self.path, meta, id)))
    }
}

const fn attrs(common: u32, file: u32, extended: u32) -> libc::attrlist {
    libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: RETURNED | common,
        volattr: 0,
        dirattr: 0,
        fileattr: file,
        forkattr: extended,
    }
}

/// Unsupported volumes/kernels retain the standard walk. Restarting only
/// after discarding the partial bulk listing prevents duplicate entries.
pub fn read_dir(
    path: &Path,
    clones: bool,
) -> io::Result<std::vec::IntoIter<io::Result<Entry>>> {
    if clones && let Ok(entries) = bulk(path) {
        return Ok(entries.into_iter());
    }
    let entries = fs::read_dir(path)?
        .map(|entry| {
            entry.map(|entry| Entry {
                path: entry.path(),
                name: entry.file_name(),
                hints: None,
                metadata: OnceLock::new(),
            })
        })
        .collect::<Vec<_>>();
    Ok(entries.into_iter())
}

fn bulk(path: &Path) -> io::Result<Vec<io::Result<Entry>>> {
    let directory = File::open(path)?;
    let mut request = attrs(libc::ATTR_CMN_NAME, 0, HINTS);
    // u64 backing provides getattrlistbulk's required eight-byte alignment.
    let mut buffer = vec![0_u64; 8192];
    let mut entries = Vec::new();
    loop {
        // SAFETY: fd is owned, request has the Darwin ABI, buffer is writable
        // and aligned; its advertised capacity is exactly its byte length.
        let count = unsafe {
            libc::getattrlistbulk(
                directory.as_raw_fd(),
                (&raw mut request).cast(),
                buffer.as_mut_ptr().cast(),
                size_of_val(buffer.as_slice()),
                u64::from(EXTENDED),
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count == 0 {
            return Ok(entries);
        }
        let bytes: Vec<u8> =
            buffer.iter().flat_map(|word| word.to_ne_bytes()).collect();
        let mut rest = bytes.as_slice();
        for _ in 0..count {
            let length = read_u32(rest, 0).ok_or_else(invalid)? as usize;
            if length < 24 {
                return Err(invalid());
            }
            let record = rest.get(..length).ok_or_else(invalid)?;
            entries.push(Ok(parse_entry(path, record)?));
            rest = rest.get(length..).ok_or_else(invalid)?;
        }
    }
}

fn parse_entry(path: &Path, record: &[u8]) -> io::Result<Entry> {
    let common = read_u32(record, 4).ok_or_else(invalid)?;
    let extended = read_u32(record, 20).ok_or_else(invalid)?;
    if common & (RETURNED | libc::ATTR_CMN_NAME)
        != RETURNED | libc::ATTR_CMN_NAME
    {
        return Err(invalid());
    }
    let offset = read_u32(record, 24).ok_or_else(invalid)?.cast_signed();
    let start = 24_usize
        .checked_add_signed(offset as isize)
        .ok_or_else(invalid)?;
    let length = read_u32(record, 28).ok_or_else(invalid)? as usize;
    let end = start.checked_add(length).ok_or_else(invalid)?;
    let name = record
        .get(start..end)
        .and_then(|s| s.strip_suffix(&[0]))
        .ok_or_else(invalid)?;
    if name.is_empty()
        || name.contains(&b'/')
        || name.contains(&0)
        || name == b"."
        || name == b".."
    {
        return Err(invalid());
    }
    let mut at = 32;
    let id = if extended & libc::ATTR_CMNEXT_CLONEID != 0 {
        at += 8;
        read_u64(record, 32).ok_or_else(invalid)?
    } else {
        0
    };
    let flags = if extended & libc::ATTR_CMNEXT_EXT_FLAGS != 0 {
        read_u64(record, at).ok_or_else(invalid)?
    } else {
        0
    };
    let name = OsString::from_vec(name.to_vec());
    Ok(Entry {
        path: path.join(&name),
        name,
        hints: Some((id, flags)),
        metadata: OnceLock::new(),
    })
}

fn private_info(path: &Path, meta: &Metadata, id: u64) -> CloneInfo {
    let mut info = CloneInfo {
        device: meta.dev(),
        id,
        ..CloneInfo::default()
    };
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return info;
    };
    // Re-read identity alongside private size: a replacement between the
    // listing/stat and this call must not receive the old file's estimate.
    let mut request = attrs(
        libc::ATTR_CMN_FILEID,
        libc::ATTR_FILE_DATAALLOCSIZE,
        libc::ATTR_CMNEXT_PRIVATESIZE | HINTS | REFCNT,
    );
    let mut buffer = [0_u8; 96];
    loop {
        // SAFETY: valid NUL-terminated path, initialized ABI request and
        // writable buffer. NOFOLLOW never asks a symlink target for data.
        let result = unsafe {
            libc::getattrlist(
                path.as_ptr(),
                (&raw mut request).cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                EXTENDED | libc::FSOPT_NOFOLLOW | libc::FSOPT_PACK_INVAL_ATTRS,
            )
        };
        if result == 0 {
            break;
        }
        if io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL)
            && request.forkattr & REFCNT != 0
        {
            request.forkattr &= !REFCNT;
            continue;
        }
        return info;
    }
    let Some(length) = read_u32(&buffer, 0) else {
        return info;
    };
    let Some(buffer) = buffer.get(..length as usize) else {
        return info;
    };
    let common = read_u32(buffer, 4).unwrap_or(0);
    let files = read_u32(buffer, 16).unwrap_or(0);
    let extended = read_u32(buffer, 20).unwrap_or(0);
    if common & libc::ATTR_CMN_FILEID == 0
        || read_u64(buffer, 24) != Some(meta.ino())
    {
        return info;
    }
    // Packed order: fileid, dataallocsize, privatesize, cloneid, flags, refcnt.
    if extended & libc::ATTR_CMNEXT_CLONEID == 0
        || read_u64(buffer, 48) != Some(id)
    {
        return info;
    }
    if extended & libc::ATTR_CMNEXT_PRIVATESIZE != 0 {
        info.private_bytes = read_u64(buffer, 40);
    }
    if files & libc::ATTR_FILE_DATAALLOCSIZE != 0 {
        info.data_bytes = read_u64(buffer, 32).unwrap_or(0);
    }
    if extended & REFCNT != 0 {
        info.references = read_u32(buffer, 64).unwrap_or(0);
    }
    info
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Darwin attribute record",
    )
}
fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// Exceptional path for followed symlinks; ordinary entries use bulk hints.
pub fn clone_info(path: &Path, meta: &Metadata) -> Option<Box<CloneInfo>> {
    let path_c = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut request = attrs(0, 0, HINTS);
    let mut buffer = [0_u8; 40];
    // SAFETY: valid path, ABI request and writable buffer of the stated size.
    let result = unsafe {
        libc::getattrlist(
            path_c.as_ptr(),
            (&raw mut request).cast(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            EXTENDED | libc::FSOPT_NOFOLLOW | libc::FSOPT_PACK_INVAL_ATTRS,
        )
    };
    if result != 0
        || read_u32(&buffer, 20)? & HINTS != HINTS
        || read_u64(&buffer, 32)? & MAY_SHARE == 0
    {
        return None;
    }
    Some(Box::new(private_info(path, meta, read_u64(&buffer, 24)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{ScanOptions, scan};
    use std::io::{Seek, SeekFrom, Write};
    use std::process::Command;

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = temp.path().join("original");
        fs::write(&source, vec![0x5a; 8 * 1024 * 1024]).expect("write");
        assert!(
            Command::new("cp")
                .arg("-c")
                .arg(&source)
                .arg(temp.path().join("clone"))
                .status()
                .expect("cp -c")
                .success()
        );
        temp
    }

    #[test]
    fn real_clones_keep_listed_bytes_and_report_sharing() {
        let temp = fixture();
        let tree = scan(temp.path(), ScanOptions::default()).expect("scan");
        assert_eq!(tree.bytes, 16 * 1024 * 1024);
        assert_eq!(tree.sharing().files, 2, "{tree:#?}");
        assert_eq!(tree.sharing().bytes, tree.bytes);
        assert_eq!(tree.sharing().duplicate_bytes, 8 * 1024 * 1024);
        assert_eq!(tree.sharing().private_bytes, 0);
        assert_eq!(tree.sharing().unknown_files, 0);
        let baseline = scan(
            temp.path(),
            ScanOptions {
                apfs_clone_metadata: false,
                ..ScanOptions::default()
            },
        )
        .expect("scan without clone metadata");
        assert_eq!(baseline.bytes, tree.bytes);
        assert_eq!(baseline.sharing().files, 0);
        let apparent = scan(
            temp.path(),
            ScanOptions {
                apparent_size: true,
                ..ScanOptions::default()
            },
        )
        .expect("apparent scan");
        assert_eq!(apparent.sharing().files, 0);
    }

    #[test]
    fn modified_clones_keep_private_bytes_and_hardlinks_are_not_clones() {
        let temp = fixture();
        let clone = temp.path().join("clone");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&clone)
            .expect("open");
        file.seek(SeekFrom::Start(1024 * 1024)).expect("seek");
        file.write_all(&[1; 4096]).expect("write");
        file.sync_all().expect("sync");
        fs::hard_link(&clone, temp.path().join("linked")).expect("hardlink");
        std::os::unix::fs::symlink(&clone, temp.path().join("symlink"))
            .expect("symlink");
        for follow_links in [false, true] {
            let tree = scan(
                temp.path(),
                ScanOptions {
                    follow_links,
                    ..ScanOptions::default()
                },
            )
            .expect("scan");
            assert_eq!(tree.sharing().files, 2, "{tree:#?}");
            assert!(tree.sharing().private_bytes >= 4096);
            assert!(tree.sharing().private_bytes < tree.sharing().bytes);
            assert_eq!(tree.sharing().duplicate_bytes, 0);
        }
    }

    #[test]
    fn unreadable_private_metadata_is_unknown_not_full_allocation() {
        let temp = fixture();
        let source = temp.path().join("original");
        let meta = fs::metadata(&source).expect("metadata");
        let info = private_info(&temp.path().join("missing"), &meta, 42);
        assert_eq!(info.private_bytes, None);
        assert_eq!(info.references, 0);
    }

    #[test]
    fn malformed_bulk_names_and_records_are_rejected() {
        assert!(parse_entry(Path::new("/"), &[]).is_err());
        let mut record = vec![0_u8; 64];
        record[4..8]
            .copy_from_slice(&(RETURNED | libc::ATTR_CMN_NAME).to_ne_bytes());
        record[24..28].copy_from_slice(&8_u32.to_ne_bytes());
        record[28..32].copy_from_slice(&3_u32.to_ne_bytes());
        record[32..35].copy_from_slice(b"ok\0");
        assert_eq!(
            parse_entry(Path::new("/"), &record).expect("entry").path(),
            Path::new("/ok")
        );
        record[32..35].copy_from_slice(b"..\0");
        assert!(parse_entry(Path::new("/"), &record).is_err());
        record[24..28].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(parse_entry(Path::new("/"), &record).is_err());
    }
}
