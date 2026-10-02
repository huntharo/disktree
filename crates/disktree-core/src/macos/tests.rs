use super::*;
use std::collections::BTreeSet;

// Build the documented wire format, including omitted attributes. Values
// distinguish adjacent fields so misaligned reads cannot pass by accident.
fn record(common: u32, file: u32, name: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in [0, common, 0, 0, file, 0] {
        bytes.extend(word.to_ne_bytes());
    }
    if common & ATTR_CMN_ERROR != 0 {
        bytes.extend(0_i32.to_ne_bytes());
    }
    let name_at = bytes.len();
    if common & libc::ATTR_CMN_NAME != 0 {
        bytes.extend([0_u8; 8]);
    }
    for (bit, value) in [
        (libc::ATTR_CMN_DEVID, (-3_i32).to_ne_bytes().to_vec()),
        (libc::ATTR_CMN_OBJTYPE, 1_u32.to_ne_bytes().to_vec()),
        (
            libc::ATTR_CMN_MODTIME,
            [123_i64.to_ne_bytes(), 456_i64.to_ne_bytes()].concat(),
        ),
        (libc::ATTR_CMN_FLAGS, 0_u32.to_ne_bytes().to_vec()),
        (libc::ATTR_CMN_FILEID, u64::MAX.to_ne_bytes().to_vec()),
    ] {
        if common & bit != 0 {
            bytes.extend(value);
        }
    }
    for (bit, value) in [
        (libc::ATTR_FILE_LINKCOUNT, 2_u32.to_ne_bytes().to_vec()),
        (libc::ATTR_FILE_ALLOCSIZE, 513_u64.to_ne_bytes().to_vec()),
        (libc::ATTR_FILE_DATALENGTH, 321_u64.to_ne_bytes().to_vec()),
    ] {
        if file & bit != 0 {
            bytes.extend(value);
        }
    }
    if common & libc::ATTR_CMN_NAME != 0 {
        let relative = i32::try_from(bytes.len() - name_at).unwrap();
        let length = u32::try_from(name.len() + 1).unwrap();
        bytes[name_at..name_at + 4].copy_from_slice(&relative.to_ne_bytes());
        bytes[name_at + 4..name_at + 8].copy_from_slice(&length.to_ne_bytes());
        bytes.extend(name);
        bytes.push(0);
    }
    bytes.resize(bytes.len().next_multiple_of(8), 0);
    let length = u32::try_from(bytes.len()).unwrap();
    bytes[..4].copy_from_slice(&length.to_ne_bytes());
    bytes
}

#[test]
fn packed_fields_keep_signed_devices_sizes_and_exact_names() {
    let parsed = Record::parse(&record(COMMON, FILE, b"n\xff")).unwrap();
    assert_eq!(parsed.name, OsString::from_vec(b"n\xff".to_vec()));
    assert_eq!(parsed.kind, Kind::File);
    let meta = parsed.metadata.unwrap();
    assert_eq!(meta.device, (-3_i64).cast_unsigned());
    assert_eq!(meta.inode, u64::MAX);
    assert_eq!(meta.links, 2);
    assert_eq!(meta.modified, 123);
    assert_eq!(meta.allocated, 1024);
    assert_eq!(meta.apparent, 321);
}

#[test]
fn missing_attributes_use_stat_without_following_symlinks() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("file"), b"actual file").unwrap();
    symlink("file", temp.path().join("link")).unwrap();
    let common = libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_NAME;
    for name in [b"file".as_slice(), b"link".as_slice()] {
        let parsed = Record::parse(&record(common, 0, name)).unwrap();
        assert!(parsed.metadata.is_none());
        let entry = parsed.entry(Arc::from(temp.path()));
        let stat = fs::symlink_metadata(entry.path()).unwrap();
        assert_eq!(entry.kind, Kind::of(stat.file_type()));
        let metadata = entry.metadata().unwrap();
        assert_eq!(metadata.apparent, stat.len());
        assert_eq!(metadata.allocated, stat.blocks() * 512);
        assert_eq!(metadata.inode, stat.ino());
    }
}

#[test]
fn returned_errors_keep_errno_even_when_the_path_exists() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("file"), b"data").unwrap();
    let mut bytes = record(COMMON, FILE, b"file");
    bytes[HEADER_BYTES..HEADER_BYTES + 4]
        .copy_from_slice(&libc::EACCES.to_ne_bytes());
    let entry = Record::parse(&bytes).unwrap().entry(Arc::from(temp.path()));
    assert_eq!(
        entry.metadata().unwrap_err().raw_os_error(),
        Some(libc::EACCES)
    );
}

#[test]
fn invalid_records_stop_iteration_once_without_panicking() {
    let temp = tempfile::tempdir().unwrap();
    let valid = record(COMMON, FILE, b"file");
    let mut bad_reference = valid.clone();
    // NAME's attrreference follows the header and entry error.
    bad_reference[28..32].copy_from_slice(&i32::MAX.to_ne_bytes());
    let mut bad_length = valid.clone();
    bad_length[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
    let mut bad_bitmap = valid.clone();
    bad_bitmap[4..8].copy_from_slice(&0_u32.to_ne_bytes());
    let mut bad_alignment = valid.clone();
    bad_alignment[..4].copy_from_slice(&25_u32.to_ne_bytes());
    for bytes in [
        bad_reference,
        bad_length,
        bad_bitmap,
        bad_alignment,
        record(COMMON, FILE, b"../escape"),
        record(COMMON, FILE, b"nul\0name"),
    ] {
        let mut reader = read_dir(temp.path()).unwrap();
        reader.buffer.bytes()[..bytes.len()].copy_from_slice(&bytes);
        reader.remaining = 1;
        assert_eq!(
            reader.next().unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(reader.next().is_none());
    }
    // Every truncation before the filename terminator is rejected.
    let name_end = 28
        + usize::try_from(i32::from_ne_bytes(
            valid[28..32].try_into().unwrap(),
        ))
        .unwrap()
        + usize::try_from(u32::from_ne_bytes(
            valid[32..36].try_into().unwrap(),
        ))
        .unwrap();
    for length in 0..name_end {
        assert!(Record::parse(&valid[..length]).is_err(), "length {length}");
    }
}

#[test]
fn fallback_lists_entries_but_never_restarts_a_partial_directory() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("file"), b"data").unwrap();
    for code in [libc::ENOTSUP, libc::ENOSYS, libc::EACCES] {
        let mut reader = read_dir(temp.path()).unwrap();
        reader
            .refill_error(io::Error::from_raw_os_error(code))
            .unwrap();
        let entries: Vec<_> = reader.map(Result::unwrap).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name, "file");
        assert_eq!(entries[0].metadata().unwrap().apparent, 4);

        let mut reader = read_dir(temp.path()).unwrap();
        reader.started = true;
        assert_eq!(
            reader
                .refill_error(io::Error::from_raw_os_error(code))
                .unwrap_err()
                .raw_os_error(),
            Some(code)
        );
        assert!(reader.fallback.is_none());
    }
}

#[test]
fn several_buffers_return_each_name_once() {
    let temp = tempfile::tempdir().unwrap();
    for index in 0..1200 {
        fs::write(temp.path().join(format!("file-{index:04}")), b"data")
            .unwrap();
    }
    let mut reader = read_dir(temp.path()).unwrap();
    let first = reader.next().unwrap().unwrap();
    assert!(
        reader.remaining < 1199,
        "the fixture spans multiple refills"
    );
    let mut names = BTreeSet::from([first.file_name]);
    for entry in reader.by_ref() {
        let entry = entry.unwrap();
        assert_eq!(entry.metadata().unwrap().apparent, 4);
        assert!(names.insert(entry.file_name), "no duplicate names");
    }
    assert_eq!(names.len(), 1200);
    assert!(reader.next().is_none());
}

#[test]
fn firmlinks_and_missing_flags_use_visible_path_metadata() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("directory")).unwrap();
    for flags in [Some(SF_FIRMLINK), None] {
        // Underlying records can disagree with the visible path. Even a
        // complete regular-file record must not bypass this lookup.
        let mut parsed =
            Record::parse(&record(COMMON, FILE, b"directory")).unwrap();
        parsed.flags = flags;
        let entry = parsed.entry(Arc::from(temp.path()));
        assert_eq!(entry.kind, Kind::Directory);
        let stat = fs::symlink_metadata(entry.path()).unwrap();
        assert_eq!(entry.metadata().unwrap().inode, stat.ino());
    }
}

#[test]
fn readable_directory_without_search_matches_standard_errors() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("restricted");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("file"), b"data").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let native: io::Result<Vec<_>> =
        read_dir(&path).and_then(Iterator::collect);
    let standard: io::Result<Vec<_>> = fs::read_dir(&path)
        .map(|entries| {
            entries
                .map(|entry| {
                    entry.map(|entry| (entry.file_name(), entry.metadata()))
                })
                .collect()
        })
        .and_then(std::convert::identity);
    // Restore access before assertions so a failed assertion cannot leave
    // cleanup unable to enter the temporary fixture.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let native = native.unwrap();
    let standard = standard.unwrap();
    assert_eq!(native.len(), 1);
    assert_eq!(standard.len(), 1);
    assert_eq!(native[0].file_name, standard[0].0);
    match (native[0].metadata(), &standard[0].1) {
        (Err(left), Err(right)) => {
            assert_eq!(left.raw_os_error(), right.raw_os_error());
            assert_eq!(left.raw_os_error(), Some(libc::EACCES));
        }
        // Elevated test runners can still stat through this directory.
        (Ok(left), Ok(right)) => assert_eq!(left.apparent, right.len()),
        _ => panic!("bulk and stat disagree on metadata access"),
    }
}

#[test]
fn directory_and_link_stats_are_deferred_until_needed() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("directory")).unwrap();
    symlink("missing", root.join("link")).unwrap();
    let entries: Vec<_> = read_dir(root).unwrap().map(Result::unwrap).collect();
    assert_eq!(entries.len(), 2);
    for entry in &entries {
        assert!(
            entry.metadata.get().is_none(),
            "enumeration must not stat this entry"
        );
    }
    // No earlier cached stat can hide a directory disappearing before the
    // consumer requests its metadata. Links still use no-follow metadata.
    fs::remove_dir(root.join("directory")).unwrap();
    for entry in entries {
        if entry.kind == Kind::Directory {
            assert_eq!(
                entry.metadata().unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
        } else {
            assert_eq!(entry.kind, Kind::Symlink);
            assert_eq!(entry.metadata().unwrap().apparent, 7);
        }
    }
}
