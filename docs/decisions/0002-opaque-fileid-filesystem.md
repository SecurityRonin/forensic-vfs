# 0002 — Opaque `FileId` node identity + streamed directory/extent iteration

**Status:** Accepted (as shipped)

## Context

A filesystem contract must name nodes. Naming them by raw inode integer lets a caller
fabricate an id or index out of range; naming them by path invites traversal bugs and
forces the filesystem to re-resolve a path on every call. Directory listing and extent
enumeration over large filesystems must not require materializing the whole listing in
memory.

## Decision

Nodes are the opaque `FileId` enum; a data stream within a node is `StreamId` (so NTFS
alternate data streams and macOS resource forks are addressable, not flattened). The
filesystem is queried by handle: `read_dir(FileId) -> DirStream`, `lookup(parent, name)`,
`meta(FileId)`, `read_at(FileId, StreamId, off, buf)`. `DirStream`/`ExtentStream`/
`NodeStream` are owned `Send` iterators, streamed not collected.

## Consequences

- A caller cannot forge a valid node from an integer it made up; ids come only from
  `root()`/`lookup()`/`read_dir()`.
- Multi-stream files (ADS, forks) are first-class rather than a lossy single-stream view.
- Directory and run enumeration is bounded-memory by construction — the iterator yields
  `VfsResult<DirEntry>` lazily, so one hostile directory with millions of entries streams
  instead of allocating.
- `read_link` takes an explicit `cap: usize`, so a hostile symlink target cannot force an
  unbounded allocation.
