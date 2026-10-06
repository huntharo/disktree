//! Compare clone accounting with the ordinary walk on the same tree:
//! `cargo run --release -p disktree-core --example scan_accounting -- PATH`
//! Append --no-clones to measure the baseline without private-size queries.

use std::path::PathBuf;
use std::time::Instant;

use disktree_core::scan::{ScanOptions, scan};

fn main() -> std::io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let root = args
        .next()
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    let clones = args.next().is_none_or(|arg| arg != "--no-clones");
    let started = Instant::now();
    let tree = scan(
        &root,
        ScanOptions {
            apfs_clone_metadata: clones,
            ..ScanOptions::default()
        },
    )?;
    println!(
        "seconds={:.3} files={} listed={} clone_files={} clone_bytes={} duplicate_bytes={} private_bytes={} unknown_clones={}",
        started.elapsed().as_secs_f64(),
        tree.files,
        tree.bytes,
        tree.sharing().files,
        tree.sharing().bytes,
        tree.sharing().duplicate_bytes,
        tree.sharing().private_bytes,
        tree.sharing().unknown_files
    );
    Ok(())
}
