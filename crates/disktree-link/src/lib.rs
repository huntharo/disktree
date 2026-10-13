//! The link between a running disktree window and the agent that drives it.
//!
//! `disktree mcp` scans on its own, so an agent needs no window. When one is
//! open, though, the agent's marks should appear in the mosaic and the
//! free-space meter, and its `show` and `review` should move the screen.
//! This crate is the wire between the two: one request per line of JSON
//! over a per-user socket, one line back.
//!
//! The socket is the trust boundary, and it is the same one the shell has:
//! only this user can reach it. There is no token and no approval step, by
//! design. The agent cannot remove anything over it; the review screen it
//! opens is where the person decides.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Incoming, Link, Listener};

#[cfg(not(unix))]
mod unsupported;
#[cfg(not(unix))]
pub use unsupported::{Incoming, Link, Listener};

/// Protocol version, bumped when a message changes shape. Both sides are
/// built from one tree, so a mismatch means an old window is still open.
pub const VERSION: u32 = 1;

/// Environment variable naming the socket, for tests and for a second copy
/// of disktree that should not meet the first.
pub const SOCKET_ENV: &str = "DISKTREE_LINK";

/// Where the window listens: `$DISKTREE_LINK` if set, else a socket in the
/// user's runtime directory.
pub fn socket_path() -> PathBuf {
    socket_path_in(
        std::env::var_os(SOCKET_ENV).map(PathBuf::from),
        std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        std::env::var_os("TMPDIR").map(PathBuf::from),
        std::env::var_os("USER").map(|user| user.to_string_lossy().into()),
    )
}

/// [`socket_path`] over given environment values, so the choice is testable.
///
/// The runtime directory and `$TMPDIR` are already the user's own, so the
/// name needs no uid there; `/tmp` is shared, so the name carries the user.
pub fn socket_path_in(
    override_path: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
    tmp_dir: Option<PathBuf>,
    user: Option<String>,
) -> PathBuf {
    if let Some(path) = override_path {
        return path;
    }
    match runtime_dir.or(tmp_dir) {
        Some(dir) => dir.join("disktree.sock"),
        None => PathBuf::from("/tmp").join(format!(
            "disktree-{}.sock",
            user.unwrap_or_else(|| "user".into())
        )),
    }
}

/// One path the agent wants marked, with what it measured so the window
/// can show a size before its own scan of that root lands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkRequest {
    pub path: PathBuf,
    pub bytes: u64,
    pub is_dir: bool,
}

/// What the agent asks of the window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Introduce the agent by its client's name; answered with [`State`].
    Hello { client: String, version: u32 },
    /// What the window shows now; answered with [`State`].
    State,
    /// Show `path` in the mosaic. `root` is the agent's scan root: when the
    /// window shows something else, it rescans from there first.
    Show { root: PathBuf, path: PathBuf },
    /// Mark these paths, under the agent's scan `root`. Already marked paths
    /// stay marked; answered with [`State`].
    Mark {
        root: PathBuf,
        targets: Vec<MarkRequest>,
    },
    /// Unmark these paths, or everything when the list is empty; answered
    /// with [`State`].
    Unmark { paths: Vec<PathBuf> },
    /// Open the review screen over what is marked.
    Review,
}

/// A marked path as the window holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mark {
    pub path: PathBuf,
    pub bytes: u64,
    pub is_dir: bool,
}

/// The volume the window measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Space {
    pub total: u64,
    pub free: u64,
    pub available: u64,
}

/// What the last removal did, kept until the next one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removal {
    /// `trash` or `permanent`.
    pub mode: String,
    pub removed: usize,
    pub failed: usize,
    /// Bytes of the targets removed, as marked.
    pub bytes: u64,
    /// Free space gained on the volume, measured before and after; `None`
    /// when the volume could not be read.
    pub freed: Option<u64>,
    /// Unix seconds when it finished.
    pub at: i64,
}

/// What the window shows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    /// The scanned root.
    pub root: PathBuf,
    /// The directory on screen.
    pub current: PathBuf,
    /// `explore`, `review`, `running` or `done`.
    pub screen: String,
    /// A scan is in progress; the tree may be absent or about to change.
    pub scanning: bool,
    /// A tree is on screen.
    pub scanned: bool,
    pub marks: Vec<Mark>,
    pub space: Option<Space>,
    pub removal: Option<Removal>,
}

/// The window's answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    State(State),
    Ok,
    Error { message: String },
}

impl Response {
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

/// A line longer than this is not a request; it is a mistake or an attack
/// on memory, and the connection is dropped.
#[cfg(unix)]
const MAX_LINE: usize = 8 * 1024 * 1024;

#[cfg(unix)]
fn encode<T: Serialize>(value: &T) -> std::io::Result<String> {
    let mut line =
        serde_json::to_string(value).map_err(std::io::Error::other)?;
    line.push('\n');
    Ok(line)
}

#[cfg(unix)]
fn decode<T: for<'de> Deserialize<'de>>(line: &str) -> std::io::Result<T> {
    serde_json::from_str(line.trim_end()).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn requests_round_trip_through_json_lines() {
        let request = Request::Mark {
            root: PathBuf::from("/home/u"),
            targets: vec![MarkRequest {
                path: PathBuf::from("/home/u/.cache"),
                bytes: 42,
                is_dir: true,
            }],
        };
        let line = encode(&request).expect("encode");
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"op\":\"mark\""));
        let back: Request = decode(&line).expect("decode");
        assert_eq!(back, request);
    }

    #[test]
    fn the_socket_is_the_override_else_a_per_user_place() {
        let custom = PathBuf::from("/x/custom.sock");
        assert_eq!(
            socket_path_in(Some(custom.clone()), None, None, None),
            custom
        );
        assert_eq!(
            socket_path_in(None, Some("/run/user/1000".into()), None, None),
            PathBuf::from("/run/user/1000/disktree.sock")
        );
        assert_eq!(
            socket_path_in(None, None, Some("/var/t".into()), None),
            PathBuf::from("/var/t/disktree.sock")
        );
        assert_eq!(
            socket_path_in(None, None, None, Some("ann".into())),
            PathBuf::from("/tmp/disktree-ann.sock")
        );
    }
}
