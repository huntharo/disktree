//! How a scan reads as text.
//!
//! An agent reads these answers as tokens, so each is a short, aligned
//! table with the number that matters first, rather than JSON that repeats
//! every key on every row. Sizes are binary units, as in the window.

use std::fmt::Write as _;
use std::path::Path;

use disktree_core::classify::{Category, Reclaim};
use disktree_core::size::{human_bytes, human_count, share, share_bar};
use disktree_core::tree::Node;

/// Width of the share bar on a row.
const BAR: usize = 8;

/// `~/x` for a path under the home directory, else the path as it is.
pub fn display(path: &Path, home: Option<&Path>) -> String {
    match home {
        Some(home) if path == home => "~".to_string(),
        Some(home) => path.strip_prefix(home).map_or_else(
            |_| path.display().to_string(),
            |rest| format!("~/{}", rest.display()),
        ),
        None => path.display().to_string(),
    }
}

/// How long ago `then` was, from `now`, in one unit: `3 d`, `2 mo`.
pub fn age(now: i64, then: i64) -> String {
    if then <= 0 {
        return "age unknown".to_string();
    }
    let seconds = (now - then).max(0);
    match seconds {
        0..3_600 => "within the hour".to_string(),
        3_600..86_400 => format!("{} h ago", seconds / 3_600),
        86_400..5_184_000 => format!("{} d ago", seconds / 86_400),
        5_184_000..63_072_000 => format!("{} mo ago", seconds / 2_592_000),
        _ => format!("{} y ago", seconds / 31_536_000),
    }
}

/// A category as the agent should say it.
pub const fn category_name(category: Category) -> &'static str {
    match category {
        Category::Code => "code",
        Category::AgentScratch => "agent scratch",
        Category::Toolchain => "toolchain",
        Category::Synced => "synced",
        Category::Git => "git",
        Category::Media => "media",
        Category::Documents => "documents",
        Category::Cache => "cache",
        Category::Other => "other",
    }
}

/// The reason space can be had back, as the window labels it.
pub const fn reclaim_name(reclaim: Reclaim) -> &'static str {
    reclaim.label()
}

/// What a node is, in one phrase after its name.
pub fn describe(node: &Node, now: i64) -> String {
    let mut parts = Vec::new();
    if node.is_dir() {
        parts.push(format!("{} files", human_count(node.files)));
    }
    if node.category != Category::Other {
        parts.push(category_name(node.category).to_string());
    }
    if let Some(reclaim) = node.reclaim {
        parts.push(format!("reclaimable: {}", reclaim_name(reclaim)));
    }
    if node.read_error {
        parts.push("unreadable".to_string());
    }
    parts.push(age(now, node.modified));
    parts.join(" \u{00b7} ")
}

/// One row of a listing: share of `total`, size, name and description.
pub fn row(node: &Node, name: &str, total: u64, now: i64) -> String {
    let mut name = name.to_string();
    if node.is_dir() {
        name.push('/');
    }
    format!(
        "{} {:>3.0}%  {:>9}  {name}  {}",
        share_bar(node.bytes, total, BAR),
        share(node.bytes, total),
        human_bytes(node.bytes),
        describe(node, now),
    )
}

/// The children of `node`, largest first, `limit` of them, with a line for
/// the rest.
pub fn children(node: &Node, limit: usize, now: i64) -> String {
    let mut out = String::new();
    let total = node.bytes.max(1);
    for child in node.children.iter().take(limit) {
        let _ = writeln!(out, "{}", row(child, &child.name, total, now));
    }
    let rest = node.children.len().saturating_sub(limit);
    if rest > 0 {
        let bytes: u64 = node
            .children
            .iter()
            .skip(limit)
            .map(|child| child.bytes)
            .sum();
        let _ = writeln!(
            out,
            "{} {:>3.0}%  {:>9}  \u{2026} {rest} more",
            share_bar(bytes, total, BAR),
            share(bytes, total),
            human_bytes(bytes),
        );
    }
    if node.children.is_empty() {
        out.push_str(if node.is_dir() {
            "(empty, or not read)\n"
        } else {
            "(a file)\n"
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use disktree_core::tree::{Metric, NodeKind, aggregate};
    use std::path::PathBuf;

    #[test]
    fn paths_under_home_are_shortened() {
        let home = PathBuf::from("/home/ann");
        assert_eq!(display(&home, Some(&home)), "~");
        assert_eq!(display(&home.join("src"), Some(&home)), "~/src");
        assert_eq!(display(Path::new("/var"), Some(&home)), "/var");
        assert_eq!(display(Path::new("/var"), None), "/var");
    }

    #[test]
    fn ages_pick_one_unit() {
        let now = 1_800_000_000;
        assert_eq!(age(now, 0), "age unknown");
        assert_eq!(age(now, now - 10), "within the hour");
        assert_eq!(age(now, now - 7_200), "2 h ago");
        assert_eq!(age(now, now - 3 * 86_400), "3 d ago");
        assert_eq!(age(now, now - 70 * 86_400), "2 mo ago");
        assert_eq!(age(now, now - 800 * 86_400), "2 y ago");
    }

    #[test]
    fn a_listing_is_largest_first_with_the_tail_summed() {
        let mut root = Node::directory("r");
        for (name, bytes) in [("a", 10), ("b", 60), ("c", 30)] {
            root.children.push(Node::entry(name, NodeKind::File, bytes));
        }
        aggregate(&mut root, Metric::Bytes);
        let text = children(&root, 2, 0);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("60 B  b "), "{}", lines[0]);
        assert!(lines[1].contains("30 B  c "), "{}", lines[1]);
        assert!(lines[2].contains("1 more"), "{}", lines[2]);
        assert!(lines[2].contains("10 B"), "{}", lines[2]);
    }
}
