//! What one connected agent knows: its scans, its marks, and the window it
//! may be driving.
//!
//! Everything here is plain Rust over `disktree-core`, with no protocol in
//! it, so the tools can be tested as functions. [`crate::server`] is the
//! thin layer that turns them into MCP tools.

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use disktree_core::classify::Category;
use disktree_core::insights::{Candidate, Finding, worth_a_look};
use disktree_core::removal::{Target, normalize, plan};
use disktree_core::scan::{ScanHandle, ScanOptions};
use disktree_core::size::{human_bytes, human_count, share};
use disktree_core::space::{
    SpaceInfo, device_for, space_info, volume_root_for, volumes,
};
use disktree_core::tree::{Node, NodeKind, path_of};
use disktree_link::{Link, MarkRequest, Request, Response, State, VERSION};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::report::{age, children, display, reclaim_name, row};

/// How many findings a scan report lists.
const INSIGHTS: usize = 8;
/// Rows a listing shows unless asked otherwise.
const DEFAULT_LIMIT: usize = 20;
/// The most rows any listing shows: past this the agent should filter.
const MAX_LIMIT: usize = 200;
/// How long to wait for a window that was just launched to start listening.
const LAUNCH_WAIT: Duration = Duration::from_secs(20);
/// A window that did not answer is not launched again sooner than this: it
/// may still be coming up, and a second one would only compete for the
/// socket.
const RELAUNCH_AFTER: Duration = Duration::from_mins(1);

/// Unix seconds now.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs().cast_signed())
}

/// Starts a disktree window on a root, for the review screen when none is
/// open. Swapped out in tests.
pub type Launcher = Box<dyn Fn(&Path) -> io::Result<()> + Send>;

/// One finished scan, kept for the rest of the session.
#[derive(Debug)]
pub struct Scan {
    pub root: PathBuf,
    pub tree: Arc<Node>,
    pub options: ScanOptions,
    /// Unix seconds when the tree landed.
    pub at: i64,
    pub elapsed: Duration,
    pub unreadable: u64,
    pub space: Option<SpaceInfo>,
    pub device: Option<String>,
    pub insights: Vec<Candidate>,
}

/// What `disktree_scan` takes.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanParams {
    /// Directory to scan. Default: the home directory.
    pub path: Option<PathBuf>,
    /// Scan the whole volume that `path` (or the home directory) is on.
    #[serde(default)]
    pub disk: bool,
    /// Measure apparent length, as `ls -l` shows it, instead of allocated
    /// blocks. Blocks are what the disk spends and what deleting frees.
    #[serde(default)]
    pub apparent_size: bool,
    /// Skip dotfiles and dot-directories. Off by default: `~/.cache` is
    /// often the largest thing in a home directory.
    #[serde(default)]
    pub skip_hidden: bool,
    /// Also measure other disks, network shares and pseudo filesystems
    /// mounted below the root. Off by default: one volume at a time.
    #[serde(default)]
    pub cross_filesystems: bool,
    /// Stop descending past this depth. Totals below it are unknown, which
    /// makes a first look at a huge tree cheap.
    pub max_depth: Option<usize>,
}

/// What `disktree_ls` takes.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LsParams {
    /// The directory to list, under a scanned root.
    pub path: PathBuf,
    /// How many entries to list, largest first. Default 20, at most 200.
    pub limit: Option<usize>,
    /// Also move the disktree window there, so the user sees what you see.
    #[serde(default)]
    pub show: bool,
}

/// What kind of entry `disktree_find` matches.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, JsonSchema, PartialEq, Eq,
)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Files and directories; a matching directory hides its contents.
    #[default]
    Any,
    File,
    Dir,
}

/// A kind of data, as `disktree_find` filters it.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CategoryName {
    Code,
    AgentScratch,
    Toolchain,
    Synced,
    Git,
    Media,
    Documents,
    Cache,
    Other,
}

impl From<CategoryName> for Category {
    fn from(name: CategoryName) -> Self {
        match name {
            CategoryName::Code => Self::Code,
            CategoryName::AgentScratch => Self::AgentScratch,
            CategoryName::Toolchain => Self::Toolchain,
            CategoryName::Synced => Self::Synced,
            CategoryName::Git => Self::Git,
            CategoryName::Media => Self::Media,
            CategoryName::Documents => Self::Documents,
            CategoryName::Cache => Self::Cache,
            CategoryName::Other => Self::Other,
        }
    }
}

/// What `disktree_find` takes.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindParams {
    /// Where to search. Default: every scanned root.
    pub path: Option<PathBuf>,
    /// `file`, `dir` or `any` (default). A matching directory is listed
    /// once, without what is inside it.
    pub kind: Option<Kind>,
    /// Only entries of at least this many bytes.
    pub min_bytes: Option<u64>,
    /// Only this kind of data.
    pub category: Option<CategoryName>,
    /// Only space that can be had back: caches, build output, package
    /// stores, installed dependencies, sync history, trash, scratch.
    #[serde(default)]
    pub reclaimable: bool,
    /// Only names containing this text, case-insensitively.
    pub name: Option<String>,
    /// Only entries not written to in this many days. For a directory, the
    /// newest write anywhere beneath it counts.
    pub older_than_days: Option<u32>,
    /// How many to list, largest first. Default 25, at most 200.
    pub limit: Option<usize>,
}

/// What `disktree_mark` and `disktree_unmark` take.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathsParams {
    /// Absolute paths under a scanned root. For `disktree_unmark`, an
    /// empty list unmarks everything.
    #[serde(default)]
    pub paths: Vec<PathBuf>,
}

/// What `disktree_show` takes.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShowParams {
    /// The path to show in the window, under a scanned root.
    pub path: PathBuf,
}

/// One connected agent's state.
pub struct Session {
    home: Option<PathBuf>,
    socket: PathBuf,
    launcher: Option<Launcher>,
    client: String,
    scans: Vec<Scan>,
    /// Marks as this session knows them: the window's when one is linked,
    /// else its own.
    marks: Vec<Target>,
    link: Option<Link>,
    /// What the window last said about itself.
    window: Option<State>,
    /// When a window was last started from here, so one that is slow to
    /// come up is not started twice.
    launched: Option<Instant>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("client", &self.client)
            .field("scans", &self.scans.len())
            .field("marks", &self.marks.len())
            .field("linked", &self.link.is_some())
            .finish_non_exhaustive()
    }
}

/// Start a disktree window on `root`, detached from this process so the
/// agent's exit does not take the window with it.
fn launch_window(root: &Path) -> io::Result<()> {
    let exe = std::env::current_exe()?;
    let mut command = Command::new(exe);
    command
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // Its own process group: a signal to the agent's group stops here.
        command.process_group(0);
    }
    command.spawn()?;
    Ok(())
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    /// A session over the real socket, able to launch a window.
    pub fn new() -> Self {
        Self::detached(
            disktree_link::socket_path(),
            Some(Box::new(launch_window)),
        )
    }

    /// A session over `socket`, launching windows with `launcher` or not at
    /// all. Tests use this with a stand-in for the window.
    pub fn detached(socket: PathBuf, launcher: Option<Launcher>) -> Self {
        Self {
            home: std::env::home_dir(),
            socket,
            launcher,
            client: "an agent".to_string(),
            scans: Vec::new(),
            marks: Vec::new(),
            link: None,
            window: None,
            launched: None,
        }
    }

    /// Remember who is connected, by the name a client gives at
    /// `initialize`, in the words the window shows.
    pub fn set_client(&mut self, name: &str) {
        let lowered = name.to_ascii_lowercase();
        self.client = if lowered.contains("claude-code")
            || lowered.contains("claude code")
        {
            "Claude Code".to_string()
        } else if lowered.contains("claude") {
            "Claude".to_string()
        } else if lowered.contains("codex") {
            "Codex".to_string()
        } else if name.trim().is_empty() {
            "an agent".to_string()
        } else {
            name.to_string()
        };
    }

    pub fn client(&self) -> &str {
        &self.client
    }

    pub fn scans(&self) -> &[Scan] {
        &self.scans
    }

    pub fn marks(&self) -> &[Target] {
        &self.marks
    }

    fn show(&self, path: &Path) -> String {
        display(path, self.home.as_deref())
    }

    // ── scanning ────────────────────────────────────────────────────────

    /// Decide what a scan request means, before the walk: the root and the
    /// options. Separate from [`run_scan`] so the walk can run with the
    /// session unlocked.
    pub fn prepare_scan(
        &self,
        params: &ScanParams,
    ) -> Result<(PathBuf, ScanOptions), String> {
        let base = match &params.path {
            Some(path) => self.absolute(path)?,
            None => self
                .home
                .clone()
                .ok_or("no path given and no home directory")?,
        };
        let root = if params.disk {
            volume_root_for(&base).unwrap_or_else(|| PathBuf::from("/"))
        } else {
            base
        };
        let metadata = std::fs::metadata(&root).map_err(|error| {
            format!("cannot read {}: {error}", root.display())
        })?;
        if !metadata.is_dir() {
            return Err(format!("{} is not a directory", root.display()));
        }
        let options = ScanOptions {
            apparent_size: params.apparent_size,
            include_hidden: !params.skip_hidden,
            one_filesystem: !params.cross_filesystems,
            max_depth: params.max_depth,
            ..ScanOptions::default()
        };
        Ok((root, options))
    }

    /// Keep a finished scan, replacing an earlier one of the same root, and
    /// say what it found.
    pub fn store_scan(&mut self, scan: Scan) -> String {
        self.scans.retain(|known| known.root != scan.root);
        let report = self.scan_report(&scan);
        self.scans.push(scan);
        report
    }

    fn scan_report(&self, scan: &Scan) -> String {
        let now = now();
        let tree = &scan.tree;
        let mut out = String::new();
        let _ = write!(
            out,
            "Scanned {} in {:.1} s: {} \u{00b7} {} files \u{00b7} {} \
             directories",
            self.show(&scan.root),
            scan.elapsed.as_secs_f64(),
            human_bytes(tree.bytes),
            human_count(tree.files),
            human_count(u64::from(tree.dirs)),
        );
        if scan.unreadable > 0 {
            let _ = write!(out, " \u{00b7} {} unreadable", scan.unreadable);
        }
        if scan.options.apparent_size {
            out.push_str(" \u{00b7} apparent sizes");
        }
        if !scan.options.include_hidden {
            out.push_str(" \u{00b7} hidden entries skipped");
        }
        if let Some(depth) = scan.options.max_depth {
            let _ = write!(out, " \u{00b7} depth limited to {depth}");
        }
        out.push('\n');
        if let Some(space) = scan.space {
            let _ = writeln!(
                out,
                "Volume {}{}: {} free of {}, {:.0}% used. This scan holds \
                 {:.0}% of what is used; the rest is outside {} or is not \
                 files (snapshots, other volumes, swap).",
                volume_root_for(&scan.root).map_or_else(
                    || "?".to_string(),
                    |root| root.display().to_string()
                ),
                scan.device
                    .as_deref()
                    .map_or_else(String::new, |device| format!(" ({device})")),
                human_bytes(space.available),
                human_bytes(space.total),
                f64::from(space.used_fraction()) * 100.0,
                share(tree.bytes, space.used().max(1)),
                self.show(&scan.root),
            );
        }
        out.push_str("Top level, largest first:\n");
        out.push_str(&children(tree, 12, now));
        if !scan.insights.is_empty() {
            out.push_str(
                "Worth a look, the biggest things that could plausibly go:\n",
            );
            for candidate in &scan.insights {
                let path = path_of(&scan.root, tree, &candidate.crumbs);
                let _ = writeln!(
                    out,
                    "  {:>9}  {}  {}",
                    human_bytes(candidate.bytes),
                    self.show(&path),
                    finding_text(&candidate.finding),
                );
            }
        }
        out.push_str(
            "Next: disktree_ls goes into a directory, disktree_find lists \
             the largest files or every cache, disktree_mark marks what \
             should go.",
        );
        out
    }

    // ── looking ─────────────────────────────────────────────────────────

    /// An absolute, normalized path: `~` expanded, relative to the working
    /// directory otherwise.
    fn absolute(&self, path: &Path) -> Result<PathBuf, String> {
        let expanded = if let Ok(rest) = path.strip_prefix("~") {
            let home = self.home.clone().ok_or("no home directory for ~")?;
            home.join(rest)
        } else if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| format!("no working directory: {error}"))?
                .join(path)
        };
        Ok(normalize(&expanded))
    }

    /// The scan holding `path`, with the node there.
    fn locate(&self, path: &Path) -> Result<Located<'_>, String> {
        let path = self.absolute(path)?;
        if self.scans.is_empty() {
            return Err(
                "Nothing is scanned yet. Call disktree_scan first; with no \
                 arguments it scans the home directory."
                    .to_string(),
            );
        }
        let scan = self
            .scans
            .iter()
            .filter(|scan| path.starts_with(&scan.root))
            .max_by_key(|scan| scan.root.as_os_str().len())
            .ok_or_else(|| {
                let roots: Vec<String> = self
                    .scans
                    .iter()
                    .map(|scan| self.show(&scan.root))
                    .collect();
                format!(
                    "{} is outside the scanned roots ({}). Scan a directory \
                     that contains it.",
                    self.show(&path),
                    roots.join(", ")
                )
            })?;
        let relative = path
            .strip_prefix(&scan.root)
            .map_err(|_| "unreachable: prefix was checked".to_string())?;
        let (crumbs, node) = scan.tree.descend(relative).ok_or_else(|| {
            format!(
                "{} is not in the scan of {}: it may be new, hidden, below \
                 the depth limit, or on another filesystem. Scan again if \
                 it should be there.",
                self.show(&path),
                self.show(&scan.root)
            )
        })?;
        Ok(Located {
            scan,
            path,
            crumbs,
            node,
        })
    }

    /// List a directory, largest first.
    pub fn ls(&mut self, params: &LsParams) -> Result<String, String> {
        let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let now = now();
        let (mut out, root) = {
            let found = self.locate(&params.path)?;
            let mut out = String::new();
            let _ = writeln!(
                out,
                "{}  {}",
                self.show(&found.path),
                crate::report::describe(found.node, now)
            );
            if !found.crumbs.is_empty() {
                let _ = writeln!(
                    out,
                    "{:.0}% of {}, which is {}",
                    share(found.node.bytes, found.scan.tree.bytes),
                    self.show(&found.scan.root),
                    human_bytes(found.scan.tree.bytes)
                );
            }
            out.push_str(&children(found.node, limit, now));
            (out, found.scan.root.clone())
        };
        if params.show {
            out.push_str(&self.show_in_window(&root, &params.path)?);
        }
        Ok(out)
    }

    /// The largest entries matching the filters, topmost matches only.
    pub fn find(&self, params: &FindParams) -> Result<String, String> {
        let limit = params.limit.unwrap_or(25).clamp(1, MAX_LIMIT);
        let now = now();
        let filter = Filter {
            kind: params.kind.unwrap_or_default(),
            min_bytes: params.min_bytes.unwrap_or(0),
            category: params.category.map(Category::from),
            reclaimable: params.reclaimable,
            name: params
                .name
                .as_deref()
                .map(str::to_lowercase)
                .filter(|name| !name.is_empty()),
            before: params
                .older_than_days
                .map(|days| now - i64::from(days) * 86_400),
        };
        let mut found: Vec<(PathBuf, &Node)> = Vec::new();
        let scope = if let Some(path) = &params.path {
            let located = self.locate(path)?;
            vec![(located.path, located.node)]
        } else {
            if self.scans.is_empty() {
                return Err(
                    "Nothing is scanned yet. Call disktree_scan first."
                        .to_string(),
                );
            }
            self.scans
                .iter()
                .map(|scan| (scan.root.clone(), &*scan.tree))
                .collect()
        };
        for (path, node) in &scope {
            for child in &node.children {
                filter.collect(&path.join(&*child.name), child, &mut found);
            }
        }
        found.sort_by_key(|(_, node)| std::cmp::Reverse(node.bytes));
        let total: u64 = found.iter().map(|(_, node)| node.bytes).sum();
        let count = found.len();
        let mut out = String::new();
        let where_ = match &params.path {
            Some(path) => self.show(&self.absolute(path)?),
            None => "the scanned roots".to_string(),
        };
        if count == 0 {
            let _ = writeln!(out, "Nothing under {where_} matches.");
            return Ok(out);
        }
        let _ = writeln!(
            out,
            "{count} match{} under {where_}, {} in all; the largest {}:",
            if count == 1 { "" } else { "es" },
            human_bytes(total),
            count.min(limit),
        );
        for (path, node) in found.iter().take(limit) {
            let _ =
                writeln!(out, "{}", row(node, &self.show(path), total, now));
        }
        Ok(out)
    }

    // ── the window ──────────────────────────────────────────────────────

    /// Whether the window link could be opened without launching anything.
    /// A new link learns the window's state and is handed the marks made
    /// here before it existed; from then on the window's marks are the
    /// marks.
    fn try_connect(&mut self) -> bool {
        if self.link.is_some() {
            return true;
        }
        let Ok(link) = Link::connect_at(&self.socket) else {
            return false;
        };
        self.link = Some(link);
        // `hello` adopts the window's marks, which would lose these.
        let mine = std::mem::take(&mut self.marks);
        let request = Request::Hello {
            client: self.client.clone(),
            version: VERSION,
        };
        if self.call(&request).is_err() {
            self.marks = mine;
            return false;
        }
        if self.push_marks(&mine).is_err() {
            return false;
        }
        true
    }

    /// Open the link, launching a window on `root` when none answers.
    fn ensure_link(&mut self, root: &Path) -> Result<(), String> {
        if self.try_connect() {
            return Ok(());
        }
        let Some(launcher) = &self.launcher else {
            return Err(format!(
                "No disktree window is open, and this session cannot open \
                 one here ({}). Start `disktree {}` yourself, then call \
                 again.",
                Link::connect_at(&self.socket)
                    .err()
                    .map_or_else(String::new, |error| error.to_string()),
                root.display()
            ));
        };
        if let Some(launched) = self.launched
            && launched.elapsed() < RELAUNCH_AFTER
        {
            return Err(format!(
                "A disktree window was started {} s ago and has not \
                 answered yet. Give it a moment and call again; if none \
                 appeared, start `disktree {}` by hand.",
                launched.elapsed().as_secs(),
                root.display()
            ));
        }
        launcher(root).map_err(|error| {
            format!("could not start a disktree window: {error}")
        })?;
        let started = Instant::now();
        self.launched = Some(started);
        while started.elapsed() < LAUNCH_WAIT {
            std::thread::sleep(Duration::from_millis(100));
            if self.try_connect() {
                self.launched = None;
                return Ok(());
            }
        }
        Err("A disktree window was started but did not answer in time. \
             Call again once it is open."
            .to_string())
    }

    /// Send one request. A failed link is dropped, so the next call tries
    /// again from the start.
    fn call(&mut self, request: &Request) -> Result<Response, String> {
        let Some(link) = &mut self.link else {
            return Err("the window is not linked".to_string());
        };
        match link.call(request) {
            Ok(Response::State(state)) => {
                self.adopt(&state);
                Ok(Response::State(state))
            }
            Ok(response) => Ok(response),
            Err(error) => {
                self.link = None;
                self.window = None;
                Err(format!("the disktree window went away: {error}"))
            }
        }
    }

    /// The window's marks are the marks: keep ours in step.
    fn adopt(&mut self, state: &State) {
        self.marks = state
            .marks
            .iter()
            .map(|mark| Target {
                hidden: is_hidden(&mark.path),
                path: mark.path.clone(),
                bytes: mark.bytes,
                is_dir: mark.is_dir,
            })
            .collect();
        self.window = Some(state.clone());
    }

    /// Hand marks made before the window linked over to it. Each answer
    /// carries the window's marks, which replace ours.
    fn push_marks(&mut self, mine: &[Target]) -> Result<(), String> {
        for root in self.roots_of(mine) {
            let targets: Vec<MarkRequest> = mine
                .iter()
                .filter(|target| target.path.starts_with(&root))
                .map(|target| MarkRequest {
                    path: target.path.clone(),
                    bytes: target.bytes,
                    is_dir: target.is_dir,
                })
                .collect();
            self.call(&Request::Mark {
                root: root.clone(),
                targets,
            })?;
        }
        Ok(())
    }

    /// Show `path` in the window, opening one on `root` if needed.
    fn show_in_window(
        &mut self,
        root: &Path,
        path: &Path,
    ) -> Result<String, String> {
        let path = self.absolute(path)?;
        self.ensure_link(root)?;
        match self.call(&Request::Show {
            root: root.to_path_buf(),
            path: path.clone(),
        })? {
            Response::Ok | Response::State(_) => {
                Ok(format!("Window: showing {}.\n", self.show(&path)))
            }
            Response::Error { message } => Err(message),
        }
    }

    pub fn show_path(&mut self, params: &ShowParams) -> Result<String, String> {
        let root = self.locate(&params.path)?.scan.root.clone();
        self.show_in_window(&root, &params.path)
    }

    /// What the window is doing, in one line, for the end of a report.
    fn window_line(&mut self) -> String {
        // A link that was already open may be stale; ask again.
        if self.try_connect() {
            let _ = self.call(&Request::State);
        }
        match &self.window {
            Some(state) => format!(
                "Window: open on {}, {} screen{}{}.",
                self.show(&state.root),
                state.screen,
                if state.scanning { ", scanning" } else { "" },
                match state.marks.len() {
                    0 => String::new(),
                    1 => ", 1 mark".to_string(),
                    n => format!(", {n} marks"),
                },
            ),
            None if self.launcher.is_some() => {
                "Window: none open. disktree_review opens one on the marks \
                 for the user to confirm; disktree_show opens one on a path."
                    .to_string()
            }
            None => "Window: none open, and none can be opened from here."
                .to_string(),
        }
    }

    // ── marking ─────────────────────────────────────────────────────────

    /// Mark paths for removal, in the window when one is open.
    pub fn mark(&mut self, params: &PathsParams) -> Result<String, String> {
        if params.paths.is_empty() {
            return Err("give at least one path to mark".to_string());
        }
        let mut targets = Vec::new();
        let mut refused = Vec::new();
        for path in &params.paths {
            let found = match self.locate(path) {
                Ok(found) => found,
                Err(reason) => {
                    refused.push(reason);
                    continue;
                }
            };
            if found.crumbs.is_empty() {
                refused.push(format!(
                    "{} is the scanned root; mark what is inside it instead",
                    self.show(&found.path)
                ));
                continue;
            }
            targets.push((
                found.scan.root.clone(),
                Target {
                    hidden: is_hidden(&found.path),
                    is_dir: found.node.is_dir(),
                    bytes: found.node.bytes,
                    path: found.path,
                },
            ));
        }
        if targets.is_empty() {
            return Err(refused.join("\n"));
        }
        if self.try_connect() {
            let roots: Vec<PathBuf> = targets
                .iter()
                .map(|(root, _)| root.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            for root in roots {
                let requests: Vec<MarkRequest> = targets
                    .iter()
                    .filter(|(scan_root, _)| *scan_root == root)
                    .map(|(_, target)| MarkRequest {
                        path: target.path.clone(),
                        bytes: target.bytes,
                        is_dir: target.is_dir,
                    })
                    .collect();
                self.call(&Request::Mark {
                    root,
                    targets: requests,
                })?;
            }
        } else {
            for (_, target) in targets {
                if !self.marks.iter().any(|known| known.path == target.path) {
                    self.marks.push(target);
                }
            }
        }
        let mut report = String::new();
        if !refused.is_empty() {
            let _ = writeln!(report, "Not marked:");
            for reason in &refused {
                let _ = writeln!(report, "  {reason}");
            }
        }
        report.push_str(&self.plan_report());
        Ok(report)
    }

    /// Unmark paths, or everything.
    pub fn unmark(&mut self, params: &PathsParams) -> Result<String, String> {
        let mut paths = Vec::new();
        for path in &params.paths {
            paths.push(self.absolute(path)?);
        }
        if self.try_connect() {
            self.call(&Request::Unmark { paths })?;
        } else if paths.is_empty() {
            self.marks.clear();
        } else {
            self.marks.retain(|target| !paths.contains(&target.path));
        }
        Ok(self.plan_report())
    }

    /// The scan roots the marks fall under, each once.
    fn roots_of(&self, marks: &[Target]) -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = Vec::new();
        for mark in marks {
            let root = self
                .scans
                .iter()
                .filter(|scan| mark.path.starts_with(&scan.root))
                .max_by_key(|scan| scan.root.as_os_str().len())
                .map(|scan| scan.root.clone())
                .or_else(|| {
                    self.window
                        .as_ref()
                        .filter(|state| mark.path.starts_with(&state.root))
                        .map(|state| state.root.clone())
                })
                .unwrap_or_else(|| {
                    mark.path
                        .parent()
                        .map_or_else(|| mark.path.clone(), Path::to_path_buf)
                });
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        roots
    }

    /// What is marked, what the guards keep back, and what it frees.
    pub fn plan_report(&mut self) -> String {
        let mut out = String::new();
        if self.marks.is_empty() {
            out.push_str("Nothing is marked.\n");
            out.push_str(&self.window_line());
            return out;
        }
        let total: u64 = self.marks.iter().map(|mark| mark.bytes).sum();
        let _ = writeln!(
            out,
            "Marked {} \u{00b7} {}",
            self.marks.len(),
            human_bytes(total)
        );
        let marks = self.marks.clone();
        for root in self.roots_of(&marks) {
            let mine: Vec<Target> = marks
                .iter()
                .filter(|mark| mark.path.starts_with(&root))
                .cloned()
                .collect();
            let plan = plan(&mine, &root);
            for target in &plan.targets {
                let _ = writeln!(
                    out,
                    "  {:>9}  {}{}",
                    human_bytes(target.bytes),
                    self.show(&target.path),
                    if target.is_dir { "/" } else { "" },
                );
            }
            if !plan.covered.is_empty() {
                let _ = writeln!(
                    out,
                    "Covered by another mark ({}): {}",
                    plan.covered.len(),
                    plan.covered
                        .iter()
                        .map(|target| self.show(&target.path))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            if !plan.blocked.is_empty() {
                let _ = writeln!(out, "Kept back ({}):", plan.blocked.len());
                for blocked in &plan.blocked {
                    let _ = writeln!(
                        out,
                        "  {}  {}",
                        self.show(&blocked.path),
                        blocked.reason
                    );
                }
            }
            let space = space_info(&root).ok();
            let device = device_for(&root);
            match space {
                Some(space) => {
                    let after = space.after_removing(plan.reclaim());
                    let _ = writeln!(
                        out,
                        "Frees {} on {}: {} free now, {} after.",
                        human_bytes(plan.reclaim()),
                        device.unwrap_or_else(|| self.show(&root)),
                        human_bytes(space.available),
                        human_bytes(after.available),
                    );
                }
                None => {
                    let _ = writeln!(
                        out,
                        "Frees {} on the volume of {}.",
                        human_bytes(plan.reclaim()),
                        self.show(&root)
                    );
                }
            }
            if plan.foreign() > 0 {
                let _ = writeln!(
                    out,
                    "Plus {} on other volumes, not counted above.",
                    human_bytes(plan.foreign())
                );
            }
            if plan.unattributed() > 0 {
                let _ = writeln!(
                    out,
                    "{} whose volume cannot be told is not counted either.",
                    human_bytes(plan.unattributed())
                );
            }
        }
        out.push_str(&self.window_line());
        out
    }

    /// Open the review screen in the window, launching one if needed.
    pub fn review(&mut self) -> Result<String, String> {
        if self.marks.is_empty() {
            return Err("Nothing is marked. disktree_mark some paths first."
                .to_string());
        }
        let marks = self.marks.clone();
        let root = self
            .roots_of(&marks)
            .into_iter()
            .next()
            .ok_or("no root for the marks")?;
        self.ensure_link(&root)?;
        match self.call(&Request::Review)? {
            Response::Error { message } => return Err(message),
            Response::Ok | Response::State(_) => {}
        }
        let _ = self.call(&Request::State);
        let total: u64 = self.marks.iter().map(|mark| mark.bytes).sum();
        Ok(format!(
            "The review screen is open in disktree: {} marked, {} to free. \
             The user decides there. Enter moves the marks to the trash, \
             where they can be recovered; permanent deletion is a choice \
             away and always asks first. Afterwards disktree_status reports \
             what was actually freed.",
            self.marks.len(),
            human_bytes(total)
        ))
    }

    // ── status ──────────────────────────────────────────────────────────

    /// Everything this session knows, in a screenful.
    pub fn status(&mut self) -> String {
        let now = now();
        let mut out = String::new();
        let _ = writeln!(
            out,
            "disktree {} serving {} over MCP. The agent marks; the person \
             removes on the review screen.",
            env!("CARGO_PKG_VERSION"),
            self.client
        );
        if self.scans.is_empty() {
            out.push_str(
                "Scans: none yet. disktree_scan with no arguments scans the \
                 home directory in seconds; disk: true scans the volume.\n",
            );
        } else {
            out.push_str("Scans:\n");
            for scan in &self.scans {
                let _ = writeln!(
                    out,
                    "  {}  {} \u{00b7} {} files \u{00b7} {} \u{00b7} took \
                     {:.1} s",
                    self.show(&scan.root),
                    human_bytes(scan.tree.bytes),
                    human_count(scan.tree.files),
                    age(now, scan.at),
                    scan.elapsed.as_secs_f64(),
                );
            }
        }
        out.push_str(&self.window_line());
        out.push('\n');
        if let Some(removal) =
            self.window.as_ref().and_then(|state| state.removal.clone())
        {
            let _ = writeln!(
                out,
                "Last removal: {} \u{00b7} {} removed \u{00b7} {} failed \
                 \u{00b7} {} marked \u{00b7} {} \u{00b7} {}",
                removal.mode,
                removal.removed,
                removal.failed,
                human_bytes(removal.bytes),
                removal.freed.map_or_else(
                    || "freed space not measured".to_string(),
                    |freed| format!(
                        "{} freed on the volume",
                        human_bytes(freed)
                    )
                ),
                age(now, removal.at),
            );
        }
        if self.marks.is_empty() {
            out.push_str("Marked: nothing.\n");
        } else {
            let total: u64 = self.marks.iter().map(|mark| mark.bytes).sum();
            let _ = writeln!(
                out,
                "Marked: {} \u{00b7} {} (disktree_mark with no new paths, or \
                 disktree_unmark, shows the plan)",
                self.marks.len(),
                human_bytes(total)
            );
        }
        let volumes: Vec<_> =
            volumes().into_iter().filter(worth_listing).collect();
        if !volumes.is_empty() {
            out.push_str("Volumes, fullest first:\n");
            for volume in volumes.iter().take(8) {
                match volume.space {
                    Some(space) => {
                        let _ =
                            writeln!(
                                out,
                                "  {}  {} free of {} ({:.0}% used){}",
                                volume.point.display(),
                                human_bytes(space.available),
                                human_bytes(space.total),
                                f64::from(space.used_fraction()) * 100.0,
                                volume.device.as_deref().map_or_else(
                                    String::new,
                                    |device| format!("  {device}")
                                ),
                            );
                    }
                    None => {
                        let _ = writeln!(
                            out,
                            "  {}  free space unknown",
                            volume.point.display()
                        );
                    }
                }
            }
        }
        out
    }
}

/// Whether a volume is one a person would call a disk: the system's own
/// slices, device files, simulator images and automount stubs are left
/// out, as is anything under a gigabyte.
fn worth_listing(volume: &disktree_core::space::Volume) -> bool {
    const GIB: u64 = 1024 * 1024 * 1024;
    let point = volume.point.to_string_lossy();
    let system = [
        "/System/Volumes/",
        "/private/",
        "/dev",
        "/Library/Developer/CoreSimulator/",
        "/proc",
        "/sys",
        "/run",
        "/boot/efi",
        "/snap/",
    ]
    .iter()
    .any(|prefix| point.starts_with(prefix));
    !system
        && volume
            .device
            .as_deref()
            .is_none_or(|device| !device.starts_with("map "))
        && volume.space.is_some_and(|space| space.total >= GIB)
}

/// Where a path landed in a scan.
struct Located<'a> {
    scan: &'a Scan,
    path: PathBuf,
    crumbs: Vec<usize>,
    node: &'a Node,
}

/// What `disktree_find` keeps.
struct Filter {
    kind: Kind,
    min_bytes: u64,
    category: Option<Category>,
    reclaimable: bool,
    name: Option<String>,
    /// Only entries last written before this Unix time.
    before: Option<i64>,
}

impl Filter {
    fn matches(&self, node: &Node) -> bool {
        let kind_ok = match self.kind {
            Kind::Any => true,
            Kind::File => !node.is_dir(),
            Kind::Dir => node.is_dir(),
        };
        kind_ok
            && node.bytes >= self.min_bytes
            && self
                .category
                .is_none_or(|category| node.category == category)
            && (!self.reclaimable || node.reclaim.is_some())
            && self
                .name
                .as_deref()
                .is_none_or(|name| node.name.to_lowercase().contains(name))
            && self.before.is_none_or(|before| {
                node.modified > 0 && node.modified < before
            })
    }

    /// Collect matches beneath `node`, topmost only. Sizes shrink going
    /// down, so a node below the minimum ends the walk there.
    fn collect<'a>(
        &self,
        path: &Path,
        node: &'a Node,
        found: &mut Vec<(PathBuf, &'a Node)>,
    ) {
        if node.bytes < self.min_bytes || node.kind == NodeKind::Other {
            return;
        }
        if self.matches(node) {
            found.push((path.to_path_buf(), node));
            return;
        }
        for child in &node.children {
            self.collect(&path.join(&*child.name), child, found);
        }
    }
}

/// A dotfile or dot-directory by name.
fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with('.'))
}

/// A finding, as a few words after its size.
fn finding_text(finding: &Finding) -> String {
    match finding {
        Finding::Reclaimable(reclaim) => {
            format!("reclaimable: {}", reclaim_name(*reclaim))
        }
        Finding::Worktrees { count, oldest_days } => format!(
            "{count} agent worktree{}, the oldest {oldest_days} d old",
            if *count == 1 { "" } else { "s" }
        ),
        Finding::StaleExperiments { count } => format!(
            "{count} experiment{} untouched for a month or more",
            if *count == 1 { "" } else { "s" }
        ),
    }
}

/// Walk `root` with `options` and keep what is needed later. Blocking;
/// the server runs it off the protocol thread.
pub fn run_scan(root: PathBuf, options: ScanOptions) -> Result<Scan, String> {
    let started = Instant::now();
    let handle = ScanHandle::spawn(root.clone(), options.clone());
    let outcome = loop {
        if let Some(outcome) = handle.poll() {
            break outcome;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let tree = outcome.map_err(|error| {
        format!("scan of {} failed: {error}", root.display())
    })?;
    let snapshot = handle.progress.snapshot();
    let at = now();
    let insights = worth_a_look(&tree, at, INSIGHTS);
    Ok(Scan {
        space: space_info(&root).ok(),
        device: device_for(&root),
        root,
        tree: Arc::new(tree),
        options,
        at,
        elapsed: started.elapsed(),
        unreadable: snapshot.errors,
        insights,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use disktree_link::{Incoming, Listener, Mark, Removal};
    #[cfg(unix)]
    use std::sync::atomic::{AtomicBool, Ordering};
    #[cfg(unix)]
    use std::sync::{Arc, Mutex};
    #[cfg(unix)]
    use std::thread;

    /// A small tree on disk: a cache, a build directory, a checkout with a
    /// large file, and a stray download.
    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::TempDir::new().expect("tempdir");
        for (path, bytes) in [
            (".cache/pip/blob.bin", 400_000_usize),
            ("src/app/target/debug/app", 300_000),
            ("src/app/Cargo.toml", 100),
            ("src/app/main.rs", 2_000),
            ("Downloads/image.iso", 250_000),
            ("notes/todo.txt", 500),
        ] {
            let file = temp.path().join(path);
            std::fs::create_dir_all(file.parent().expect("parent"))
                .expect("mkdir");
            std::fs::write(&file, vec![b'x'; bytes]).expect("write");
        }
        temp
    }

    /// Apparent sizes, so the numbers are the bytes written, not blocks.
    fn scanned(session: &mut Session, root: &Path) -> String {
        let (root, options) = session
            .prepare_scan(&ScanParams {
                path: Some(root.to_path_buf()),
                apparent_size: true,
                ..ScanParams::default()
            })
            .expect("prepare");
        let scan = run_scan(root, options).expect("scan");
        session.store_scan(scan)
    }

    fn unlinked(dir: &Path) -> Session {
        Session::detached(dir.join("no-window.sock"), None)
    }

    #[test]
    fn a_scan_reports_totals_the_top_level_and_findings() {
        let temp = fixture();
        let mut session = unlinked(temp.path());
        let report = scanned(&mut session, temp.path());
        assert!(report.starts_with("Scanned "), "{report}");
        assert!(report.contains("6 files"), "{report}");
        assert!(report.contains(".cache/"), "{report}");
        assert!(report.contains("Top level, largest first:"), "{report}");
        assert!(report.contains("Next: disktree_ls"), "{report}");
        assert_eq!(session.scans().len(), 1);
        // Scanning again replaces, not duplicates.
        scanned(&mut session, temp.path());
        assert_eq!(session.scans().len(), 1);
    }

    #[test]
    fn ls_needs_a_scan_and_then_lists_largest_first() {
        let temp = fixture();
        let mut session = unlinked(temp.path());
        let missing = session
            .ls(&LsParams {
                path: temp.path().join("src"),
                ..LsParams::default()
            })
            .expect_err("nothing scanned");
        assert!(missing.contains("disktree_scan"), "{missing}");

        scanned(&mut session, temp.path());
        let listing = session
            .ls(&LsParams {
                path: temp.path().to_path_buf(),
                limit: Some(2),
                show: false,
            })
            .expect("ls");
        let lines: Vec<&str> = listing.lines().collect();
        // Header, then .cache (400k), src (302.1k), then the rest.
        assert!(lines[1].contains(".cache/"), "{listing}");
        assert!(lines[2].contains("src/"), "{listing}");
        assert!(lines[3].contains("2 more"), "{listing}");

        let outside = session
            .ls(&LsParams {
                path: PathBuf::from("/definitely/elsewhere"),
                ..LsParams::default()
            })
            .expect_err("outside");
        assert!(outside.contains("outside the scanned roots"), "{outside}");
    }

    #[test]
    fn find_filters_by_kind_size_name_and_reclaim() {
        let temp = fixture();
        let mut session = unlinked(temp.path());
        scanned(&mut session, temp.path());

        let files = session
            .find(&FindParams {
                kind: Some(Kind::File),
                min_bytes: Some(200_000),
                ..FindParams::default()
            })
            .expect("find");
        assert!(files.contains("blob.bin"), "{files}");
        assert!(files.contains("image.iso"), "{files}");
        assert!(files.contains("debug/app"), "{files}");
        assert!(!files.contains("todo.txt"), "{files}");

        let reclaim = session
            .find(&FindParams {
                reclaimable: true,
                ..FindParams::default()
            })
            .expect("find");
        // The topmost reclaimable directory, once, without its contents.
        assert!(reclaim.contains(".cache/"), "{reclaim}");
        assert!(reclaim.contains("target/"), "{reclaim}");
        assert!(!reclaim.contains("blob.bin"), "{reclaim}");

        let named = session
            .find(&FindParams {
                name: Some("ISO".into()),
                ..FindParams::default()
            })
            .expect("find");
        assert!(named.starts_with("1 match "), "{named}");

        let none = session
            .find(&FindParams {
                name: Some("nothing-here".into()),
                ..FindParams::default()
            })
            .expect("find");
        assert!(none.contains("Nothing"), "{none}");
    }

    #[test]
    fn marks_are_planned_with_the_guards_and_without_a_window() {
        let temp = fixture();
        let mut session = unlinked(temp.path());
        scanned(&mut session, temp.path());

        let root_refused = session
            .mark(&PathsParams {
                paths: vec![temp.path().to_path_buf()],
            })
            .expect_err("the root alone");
        assert!(root_refused.contains("scanned root"), "{root_refused}");
        // With a good path beside it, the root is reported and the rest
        // is marked.
        let partial = session
            .mark(&PathsParams {
                paths: vec![
                    temp.path().to_path_buf(),
                    temp.path().join("notes"),
                ],
            })
            .expect("one of two");
        assert!(partial.starts_with("Not marked:"), "{partial}");
        assert!(partial.contains("Marked 1"), "{partial}");
        session
            .unmark(&PathsParams { paths: vec![] })
            .expect("clear");

        let plan = session
            .mark(&PathsParams {
                paths: vec![
                    temp.path().join(".cache"),
                    temp.path().join("src/app/target"),
                    // Inside the first mark: covered, not counted twice.
                    temp.path().join(".cache/pip"),
                ],
            })
            .expect("mark");
        assert!(plan.starts_with("Marked 3"), "{plan}");
        assert!(plan.contains("Covered by another mark (1)"), "{plan}");
        assert!(plan.contains("Frees"), "{plan}");
        assert!(plan.contains("Window: none open, and none can be opened"));
        assert_eq!(session.marks().len(), 3);

        let fewer = session
            .unmark(&PathsParams {
                paths: vec![temp.path().join(".cache/pip")],
            })
            .expect("unmark");
        assert!(fewer.starts_with("Marked 2"), "{fewer}");
        let none = session
            .unmark(&PathsParams { paths: vec![] })
            .expect("unmark all");
        assert!(none.starts_with("Nothing is marked."), "{none}");

        let review = session.review().expect_err("nothing to review");
        assert!(review.contains("Nothing is marked"), "{review}");
    }

    /// A stand-in for the window: answers over the real socket the way the
    /// app does, and records what it was asked.
    #[cfg(unix)]
    struct FakeWindow {
        listener: Arc<Listener>,
        asked: Arc<Mutex<Vec<Request>>>,
        marks: Arc<Mutex<Vec<Mark>>>,
        stop: Arc<AtomicBool>,
    }

    #[cfg(unix)]
    impl FakeWindow {
        fn open(socket: &Path, root: &Path) -> Self {
            let listener = Arc::new(Listener::bind_at(socket).expect("bind"));
            let asked = Arc::new(Mutex::new(Vec::new()));
            let marks: Arc<Mutex<Vec<Mark>>> = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (l, a, m, s) = (
                Arc::clone(&listener),
                Arc::clone(&asked),
                Arc::clone(&marks),
                Arc::clone(&stop),
            );
            let root = root.to_path_buf();
            thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    for incoming in l.drain() {
                        if let Incoming::Request { request, reply, .. } =
                            incoming
                        {
                            a.lock().expect("asked").push(request.clone());
                            let mut marks = m.lock().expect("marks");
                            match &request {
                                Request::Mark { targets, .. } => {
                                    for target in targets {
                                        if !marks.iter().any(|mark| {
                                            mark.path == target.path
                                        }) {
                                            marks.push(Mark {
                                                path: target.path.clone(),
                                                bytes: target.bytes,
                                                is_dir: target.is_dir,
                                            });
                                        }
                                    }
                                }
                                Request::Unmark { paths }
                                    if paths.is_empty() =>
                                {
                                    marks.clear();
                                }
                                Request::Unmark { paths } => {
                                    marks.retain(|mark| {
                                        !paths.contains(&mark.path)
                                    });
                                }
                                _ => {}
                            }
                            let state = State {
                                version: VERSION,
                                root: root.clone(),
                                current: root.clone(),
                                screen: if matches!(request, Request::Review) {
                                    "review".into()
                                } else {
                                    "explore".into()
                                },
                                scanning: false,
                                scanned: true,
                                marks: marks.clone(),
                                space: None,
                                removal: Some(Removal {
                                    mode: "trash".into(),
                                    removed: 2,
                                    failed: 0,
                                    bytes: 700_000,
                                    freed: Some(690_000),
                                    at: now() - 120,
                                }),
                            };
                            reply.send(match request {
                                Request::Show { .. } | Request::Review => {
                                    Response::Ok
                                }
                                _ => Response::State(state),
                            });
                        }
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            });
            Self {
                listener,
                asked,
                marks,
                stop,
            }
        }

        fn asked(&self) -> Vec<Request> {
            self.asked.lock().expect("asked").clone()
        }
    }

    #[cfg(unix)]
    impl Drop for FakeWindow {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            let _ = &self.listener;
            let _ = &self.marks;
        }
    }

    #[cfg(unix)]
    #[test]
    fn with_a_window_open_marks_live_there_and_review_opens_it() {
        let temp = fixture();
        let socket = temp.path().join("window.sock");
        let window = FakeWindow::open(&socket, temp.path());
        let mut session = Session::detached(socket, None);
        session.set_client("claude-code");
        scanned(&mut session, temp.path());

        let plan = session
            .mark(&PathsParams {
                paths: vec![temp.path().join(".cache")],
            })
            .expect("mark");
        assert!(plan.starts_with("Marked 1"), "{plan}");
        assert!(plan.contains("Window: open on"), "{plan}");
        assert!(plan.contains("1 mark"), "{plan}");

        let shown = session
            .ls(&LsParams {
                path: temp.path().join("src"),
                limit: None,
                show: true,
            })
            .expect("ls with show");
        assert!(shown.contains("Window: showing"), "{shown}");

        let review = session.review().expect("review");
        assert!(review.contains("review screen is open"), "{review}");

        let status = session.status();
        assert!(status.contains("Claude Code"), "{status}");
        assert!(status.contains("Last removal: trash"), "{status}");
        assert!(status.contains("review screen"), "{status}");

        let asked = window.asked();
        assert!(
            matches!(asked[0], Request::Hello { ref client, .. } if client == "Claude Code")
        );
        assert!(
            asked
                .iter()
                .any(|request| matches!(request, Request::Mark { .. }))
        );
        assert!(
            asked
                .iter()
                .any(|request| matches!(request, Request::Show { .. }))
        );
        assert!(
            asked
                .iter()
                .any(|request| matches!(request, Request::Review))
        );
    }

    #[cfg(unix)]
    #[test]
    fn marks_made_before_the_window_opened_are_handed_over() {
        let temp = fixture();
        let socket = temp.path().join("window.sock");
        let mut session = Session::detached(socket.clone(), None);
        scanned(&mut session, temp.path());
        session
            .mark(&PathsParams {
                paths: vec![temp.path().join("Downloads")],
            })
            .expect("mark offline");
        assert_eq!(session.marks().len(), 1);

        let window = FakeWindow::open(&socket, temp.path());
        let review = session.review().expect("review");
        assert!(review.contains("1 marked"), "{review}");
        let asked = window.asked();
        let handed = asked.iter().find_map(|request| match request {
            Request::Mark { targets, .. } => Some(targets.clone()),
            _ => None,
        });
        assert_eq!(
            handed.map(|targets| targets[0].path.clone()),
            Some(temp.path().join("Downloads"))
        );
    }

    #[test]
    fn client_names_read_like_products() {
        let temp = fixture();
        let mut session = unlinked(temp.path());
        session.set_client("claude-code");
        assert_eq!(session.client(), "Claude Code");
        session.set_client("codex-cli");
        assert_eq!(session.client(), "Codex");
        session.set_client("claude-ai");
        assert_eq!(session.client(), "Claude");
        session.set_client("zed");
        assert_eq!(session.client(), "zed");
        session.set_client("");
        assert_eq!(session.client(), "an agent");
    }
}
