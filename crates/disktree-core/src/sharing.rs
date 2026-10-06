//! APFS sharing, reported separately from the treemap's allocated bytes.
//!
//! Ported from huntharo/diskhound's clone accounting (PR #4). Clone IDs
//! describe full data-fork clones, not every shared extent of modified files.
//! The source license is retained in `licenses/diskhound-MIT.txt`.

use rustc_hash::FxHashMap;

use crate::tree::Node;

/// Metadata retained only for files that may share allocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CloneInfo {
    pub device: u64,
    pub id: u64,
    pub references: u32,
    pub private_bytes: Option<u64>,
    /// Clone identity describes the data fork, not resource forks or xattrs.
    pub data_bytes: u64,
}

/// Derived figures; none changes `Node::bytes` or a tile's weight.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sharing {
    pub files: u64,
    pub bytes: u64,
    pub private_bytes: u64,
    pub duplicate_bytes: u64,
    pub unknown_files: u64,
    /// More than one million distinct groups: repeated-byte reporting is partial.
    pub groups_truncated: bool,
}

impl Sharing {
    /// Conservative estimate: shared extents are excluded even if all their
    /// references are selected together. Snapshots can retain other blocks.
    pub const fn reclaimable(self, listed: u64) -> u64 {
        listed
            .saturating_sub(self.bytes)
            .saturating_add(self.private_bytes)
    }
}

#[derive(Debug)]
struct Group {
    bytes: u64,
    count: u64,
}

impl Group {
    const fn duplicates(&self) -> u64 {
        self.bytes.saturating_mul(self.count - 1)
    }
}

type Groups = FxHashMap<(u64, u64), Group>;
// Bound temporary grouping memory on volumes with millions of clone IDs.
const MAX_CLONE_GROUPS: usize = 1_000_000;

/// Small-to-large merging avoids walking every subtree for every ancestor.
/// Hardlink duplicates already have zero weight when this pass runs.
pub(crate) fn refresh(node: &mut Node) {
    collect(node, MAX_CLONE_GROUPS);
}

fn collect(node: &mut Node, limit: usize) -> Groups {
    let mut groups = Groups::default();
    let mut summary = Sharing::default();
    if let Some(info) = node.clone_info.as_deref().filter(|_| node.bytes > 0) {
        summary.files = 1;
        summary.bytes = node.bytes;
        summary.private_bytes = info.private_bytes.unwrap_or(0).min(node.bytes);
        summary.unknown_files = u64::from(info.private_bytes.is_none());
        if info.id != 0 && info.references >= 2 {
            groups.insert(
                (info.device, info.id),
                Group {
                    bytes: info.data_bytes.min(node.bytes),
                    count: 1,
                },
            );
        }
    }
    for child in &mut node.children {
        let mut child_groups = collect(child, limit);
        summary.duplicate_bytes = summary
            .duplicate_bytes
            .saturating_add(child.sharing().duplicate_bytes);
        summary.groups_truncated |= child.sharing().groups_truncated;
        summary.files += child.sharing().files;
        summary.bytes = summary.bytes.saturating_add(child.sharing().bytes);
        summary.private_bytes = summary
            .private_bytes
            .saturating_add(child.sharing().private_bytes);
        summary.unknown_files += child.sharing().unknown_files;
        if groups.len() < child_groups.len() {
            std::mem::swap(&mut groups, &mut child_groups);
        }
        for (key, group) in child_groups {
            if groups.len() >= limit && !groups.contains_key(&key) {
                summary.groups_truncated = true;
                continue;
            }
            groups
                .entry(key)
                .and_modify(|old| {
                    // A scan is not atomic. Use the smaller observation when
                    // a file changes while its clone group is being measured.
                    let before =
                        old.duplicates().saturating_add(group.duplicates());
                    old.bytes = old.bytes.min(group.bytes);
                    old.count += group.count;
                    summary.duplicate_bytes = summary
                        .duplicate_bytes
                        .saturating_sub(before)
                        .saturating_add(old.duplicates());
                })
                .or_insert(group);
        }
    }
    node.sharing = (summary.files > 0).then(|| Box::new(summary));
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{Metric, NodeKind, Seen, aggregate, aggregate_deduped};

    fn clone(name: &str, device: u64, id: u64, private: Option<u64>) -> Node {
        let mut node = Node::entry(name, NodeKind::File, 100);
        node.clone_info = Some(Box::new(CloneInfo {
            device,
            id,
            references: 2,
            private_bytes: private,
            data_bytes: 80,
        }));
        node
    }

    #[test]
    fn group_limit_marks_the_summary_partial_without_losing_private_bytes() {
        let mut root = Node::directory("root");
        root.children =
            vec![clone("a", 1, 1, Some(20)), clone("b", 1, 2, Some(20))];
        aggregate(&mut root, Metric::Bytes);
        collect(&mut root, 1);
        assert!(root.sharing().groups_truncated);
        assert_eq!(root.sharing().private_bytes, 40);
    }

    #[test]
    fn groups_are_volume_scoped_and_only_data_forks_are_duplicated() {
        let mut root = Node::directory("root");
        root.children = vec![
            clone("a", 1, 42, Some(20)),
            clone("b", 1, 42, Some(20)),
            clone("c", 2, 42, Some(20)),
        ];
        aggregate(&mut root, Metric::Bytes);
        assert_eq!(root.bytes, 300);
        assert_eq!(root.sharing().duplicate_bytes, 80);
        assert_eq!(root.sharing().reclaimable(root.bytes), 60);
        aggregate(&mut root, Metric::Files);
        assert_eq!(root.sharing().duplicate_bytes, 80);
    }

    #[test]
    fn unknown_and_oversized_private_values_stay_conservative() {
        let mut root = Node::directory("root");
        root.children = vec![
            clone("a", 1, 1, None),
            clone("b", 1, 2, Some(200)),
            Node::entry("ordinary", NodeKind::File, 30),
        ];
        aggregate(&mut root, Metric::Bytes);
        assert_eq!(root.sharing().unknown_files, 1);
        assert_eq!(root.sharing().reclaimable(root.bytes), 130);
    }

    #[test]
    fn deduplicated_hardlinks_do_not_inflate_sharing() {
        let mut root = Node::directory("root");
        root.children =
            vec![clone("a", 1, 1, Some(0)), clone("b", 1, 1, Some(0))];
        for node in &mut root.children {
            node.inode =
                Some((1, std::num::NonZeroU64::new(123).expect("inode")));
        }
        aggregate_deduped(&mut root, Metric::Bytes, &Seen::new());
        assert_eq!(root.sharing().files, 1);
        assert_eq!(root.sharing().bytes, 100);
        assert_eq!(root.sharing().duplicate_bytes, 0);
    }

    #[test]
    fn clone_groups_merge_across_directories_and_refresh_after_removal() {
        let mut root = Node::directory("root");
        for name in ["a", "b"] {
            let mut dir = Node::directory(name);
            dir.children.push(clone("file", 1, 1, Some(0)));
            root.children.push(dir);
        }
        aggregate(&mut root, Metric::Bytes);
        assert_eq!(root.sharing().duplicate_bytes, 80);
        assert_eq!(root.children[0].sharing().duplicate_bytes, 0);
        root.children.pop();
        aggregate(&mut root, Metric::Bytes);
        assert_eq!(root.sharing().duplicate_bytes, 0);
        assert_eq!(root.sharing().files, 1);
    }
}
