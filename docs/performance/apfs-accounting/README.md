# APFS accounting and bounded selection work

Validated on macOS 26.6.1, Apple silicon, Rust 1.97, 2026-10-14.
The baseline is PR #3 at `e9b4996`; the tests below exercise this branch's
accepted-set accounting. No new home-directory or whole-volume benchmark
was run. Earlier scan timings in the PR describe older implementations.

## Accounting regressions

The isolated baseline source snapshot failed both tests in
[regression-red.log](regression-red.log):

| Selection | Baseline estimate | Required result |
| --- | ---: | ---: |
| Two complete synthetic clones, 80 shared bytes | 0 B | 80 B once |
| Charged name of a 4 KiB file with a retained hardlink | 4 KiB | 0 B |

The checked-in sharing tests now cover complete groups across directories,
separate marks, hardlinks both within and across those marks, unknown real
volume identity, missing private metadata, changed metadata, followed files
and directories, grouping limits, and modified clones. Real APFS tests use
`cp -c`, hardlinks, followed symlinks and a resource fork. The window test
marks separate clone paths, changes tile metric, draws review/confirmation,
checks warm plan reuse, changes the selection and replaces the scan tree.

`ATTR_CMNEXT_REALDEVID` scopes grouping and cache reuse. Ordinary `st_dev`
can alias APFS System and Data volumes on this host. Missing real identity
never permits grouping or cross-file metadata reuse.

An 8 MiB original and two full clones retain 24 MiB of listed allocation.
Marking only the two copies estimates 0 B. Marking all three estimates
8 MiB, once, before snapshot/open-file effects. A retained hardlink prevents
crediting its inode, even if that inode owns the tree's nonzero weight.
Followed symlinks cannot authorize freeing their targets' file data.

The private-size attribute measures the data fork. In the real resource-fork
fixture it remains zero while all-fork allocation grows by 4 KiB. The
complete clone group's range is therefore 8 MiB to 8 MiB + 4 KiB; the lone
copy's range is 0 to 4 KiB. That unmeasured fork allocation never inflates the
meter's lower estimate. Bounds describe scan observations, not guaranteed
changes to volume free space: snapshots, open files and filesystem changes
still matter. The final outcome uses measured free space.

## Work and memory bounds

The main-only red/green proof is separate in
[PR #9](https://github.com/huntharo/disktree/pull/9) and
[mark-resolution](../mark-resolution/README.md). This branch incorporates
that fix and reuses one lazy sibling resolver per accounting cache miss.
One mark is one queued path, independent of its descendant count. The
1,024-mark case is a stress workload, with no usage telemetry establishing
that it is common. The earlier 6.60 s measured four forced Explore draws
and eight prepares, not a scan or one click.
[Individual interaction evidence](../mark-resolution/interactions.md)
separates Space, hover and Review, includes smaller queues, and records
render/plan counts with zero scan refreshes. Its timings compare the
isolated main-only snapshots, not this APFS feature branch.
Removal authorization remains fresh on every plan and in the worker.

Selected subtrees merge bounded maps small to large: expected
`O(K log K)` total map work for K visited entries, without mark-pair or
clone-group-pair comparisons. Unchanged accepted sets reuse estimates by
weak tree identity, root and accepted paths. Single marked subtrees use
precomputed scan summaries; ordinary aggregated subtrees need no second
walk. Tree replacement and changed accepted paths invalidate reuse. Tile
metric never changes removal byte units. Fresh guards and target sorting
still cost work per plan; the entire UI is not claimed to be constant time.

[budget-green.log](budget-green.log) records operation counts with marks,
clone groups and hardlink names growing together:

| Groups | Marked directories | Leaf entries | Accounting operations |
| ---: | ---: | ---: | ---: |
| 128 | 256 | 512 | 1,790 |
| 1,024 | 2,048 | 4,096 | 14,334 |

Eight times the workload costs 8.01 times the operations. The test enforces
both a 16x ratio ceiling and an absolute ceiling of 40 operations per group.
This measures accounting operations, not wall-clock speed or kernel work.

Metadata queries run in directory workers. A per-scan cache has 64 mutex
shards, with no lock held during filesystem queries and no clone-result
channel or dedicated consumer. Reuse requires a known real device, a clone
ID, a full-sharing bulk flag, a confirmed zero-private sample, and matching
all-fork/data-fork allocation. An observed reference count limits reuse;
hardlink aliases do not spend another clone-reference slot. Modified or
unknown observations are measured individually. Races may duplicate first
queries. Cache tests grow both groups and members: 128 groups x 128 members
need 128 measurement callbacks, and 1,024 x 1,024 need 1,024, instead of one
per member. These are deterministic callback counts, not measured speedups.

The cache caps groups and exceptional hardlink identities independently at
at most one million entries, distributed across shards. Scan summaries cap
clone-group and hardlink maps separately at one million entries. Crossing a
limit keeps private lower estimates, drops unproved group credit, and marks
accounting partial. Leaf metadata uses one sparse box; it no longer copies
a boxed clone result or allocates a second sharing box per clone. The Node
size budget remains 104 bytes, versus upstream's 88-byte layout.

## Reproduce

```sh
cargo xtask lint
cargo xtask test
cargo test -p disktree-core selected_set_work -- --nocapture
cargo test -p disktree-core clone_cache -- --nocapture
cargo test -p disktree-core macos::clone_tests -- --nocapture
cargo run --release -p disktree-core --example scan_accounting -- PATH
```

Local validation: lint passed; 79 window/app, 174 core and 3 xtask tests passed;
two existing core tests and the opt-in interaction timing test remained
ignored in the normal suite. The interaction timing test was also run
explicitly and passed on the combined branch. No private file contents were
inspected and no user files were removed by this investigation.
