use super::*;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{File, FileTimes};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::symlink;
use std::time::{Duration, UNIX_EPOCH};

fn native(path: &Path) -> Vec<Named<crate::macos::Entry>> {
    list(path, None)
        .expect("list")
        .map(Result::unwrap)
        .collect()
}

fn standard(entry: DirEntry) -> Named<DirEntry> {
    Named {
        name: entry.file_name().to_string_lossy().into(),
        entry,
    }
}

fn same_facts(native: &Named<crate::macos::Entry>, standard: &Named<DirEntry>) {
    assert_eq!(
        native.entry_path(Path::new("")),
        standard.entry_path(Path::new(""))
    );
    assert_eq!(native.name(), standard.name());
    for apparent in [false, true] {
        let left = native.facts(apparent).expect("native facts");
        let right = standard.facts(apparent).expect("standard facts");
        assert_eq!(
            left.size,
            right.size,
            "{}",
            native.entry.file_name.display()
        );
        assert_eq!(left.identity, right.identity);
        assert_eq!(left.modified, right.modified);
        assert_eq!(left.shared, right.shared);
    }
    match (native.listing().unwrap(), standard.listing().unwrap()) {
        (Listing::Directory, Listing::Directory) => {
            let left = native.directory().unwrap();
            let right = standard.directory().unwrap();
            assert_eq!(left.device, right.device);
            assert_eq!(left.evicted, right.evicted);
        }
        (Listing::Symlink, Listing::Symlink) => {}
        (Listing::Leaf(left), Listing::Leaf(right)) => assert_eq!(left, right),
        _ => panic!("native and standard file types differ"),
    }
}

#[test]
fn bulk_metadata_matches_stat_accounting_and_names() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("directory")).unwrap();
    fs::write(root.join("file"), vec![7_u8; 8193]).unwrap();
    fs::hard_link(root.join("file"), root.join("hardlink")).unwrap();
    symlink("file", root.join("symlink")).unwrap();
    symlink("missing", root.join("dangling")).unwrap();
    fs::write(root.join(".hidden"), b"hidden").unwrap();
    fs::write(root.join("café"), b"unicode").unwrap();
    let sparse = File::create(root.join("sparse")).unwrap();
    sparse.set_len(8 * 1024 * 1024).unwrap();
    fs::write(root.join("forked"), b"data").unwrap();
    fs::write(root.join("forked/..namedfork/rsrc"), vec![9_u8; 16385])
        .expect("resource fork");
    let standard: HashMap<_, _> = fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), standard(entry))
        })
        .collect();
    let entries = native(root);
    assert_eq!(entries.len(), standard.len());
    for entry in entries {
        same_facts(&entry, &standard[&entry.entry.file_name]);
    }
}

#[test]
fn native_paths_preserve_non_utf8_names() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("file"), b"data").unwrap();
    let mut entry = native(temp.path()).pop().unwrap();
    // APFS rejects malformed UTF-8 at creation. Inject a returned name to
    // verify that only display, never path resolution, is lossy.
    entry.entry.file_name = OsString::from_vec(vec![b'n', 0xff]);
    entry.name = entry.entry.file_name.to_string_lossy().into();
    assert_eq!(
        entry.entry_path(temp.path()),
        temp.path().join(&entry.entry.file_name)
    );
    assert_eq!(entry.name(), "n�");
    assert_eq!(&*entry.take_name(), "n�");
    assert!(entry.name().is_empty());
}

#[test]
fn bulk_timestamps_keep_pre_epoch_semantics() {
    let temp = tempfile::tempdir().unwrap();
    for (name, time) in [
        ("before", UNIX_EPOCH - Duration::from_millis(500)),
        ("after", UNIX_EPOCH + Duration::from_millis(1500)),
    ] {
        let file = File::create(temp.path().join(name)).unwrap();
        file.set_times(FileTimes::new().set_modified(time)).unwrap();
    }
    for entry in native(temp.path()) {
        let standard = fs::read_dir(temp.path())
            .unwrap()
            .map(Result::unwrap)
            .find(|other| other.file_name() == entry.entry.file_name)
            .unwrap();
        same_facts(&entry, &self::standard(standard));
        assert_eq!(
            entry.facts(false).unwrap().modified,
            i64::from(entry.entry.file_name == "after")
        );
    }
}

#[test]
fn native_metadata_errors_keep_os_codes() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("file"), b"data").unwrap();
    let mut entry = native(temp.path()).pop().unwrap();
    // Inject a per-entry failure, without
    // depending on the test runner's privileges or racing another thread.
    for code in [rustix::io::Errno::ACCESS, rustix::io::Errno::NOENT] {
        entry.entry.metadata =
            Err(io::Error::from_raw_os_error(code.raw_os_error()));
        assert_eq!(
            entry.facts(false).err().unwrap().raw_os_error(),
            Some(code.raw_os_error())
        );
    }
}

#[test]
fn directory_facts_are_rechecked_before_descent() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    fs::create_dir(&path).unwrap();
    let entry = native(temp.path()).pop().unwrap();
    assert!(!entry.directory().unwrap().evicted);
    fs::remove_dir(path).unwrap();
    assert_eq!(
        entry.directory().err().unwrap().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn evicted_directory_facts_prevent_descent() {
    struct Evicted(PathBuf);
    impl Listed for Evicted {
        fn entry_path(&self, _: &Path) -> PathBuf {
            self.0.clone()
        }
        fn name(&self) -> &'static str {
            "cloud"
        }
        fn take_name(&mut self) -> Box<str> {
            "cloud".into()
        }
        fn listing(&self) -> io::Result<Listing> {
            Ok(Listing::Directory)
        }
        fn facts(&self, _: bool) -> io::Result<Facts> {
            panic!("directory must not be measured as a leaf")
        }
        fn directory(&self) -> io::Result<Directory> {
            Ok(Directory {
                device: 0,
                evicted: true,
            })
        }
    }
    let context = WalkContext {
        known: None,
        options: ScanOptions::default(),
        progress: Arc::new(ScanProgress::default()),
        root_device: Mutex::new(None),
        foreign_mounts: OnceLock::new(),
        never_scanned: OnceLock::new(),
        visited_dirs: Mutex::new(FxHashSet::default()),
        root: Mutex::new(None),
        volume: OnceLock::new(),
    };
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("cloud")).unwrap();
    fs::write(temp.path().join("cloud/local-child"), b"not visited").unwrap();
    // Synthetic facts exercise the descent decision, not a live provider.
    assert!(matches!(
        context.classify(temp.path(), &mut Evicted(temp.path().join("cloud"))),
        Classified::Skipped
    ));
    assert_eq!(context.progress.snapshot().dirs, 0);
}
