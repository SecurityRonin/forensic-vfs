# 0001 — Positioned-read, cursorless, read-only byte source

**Status:** Accepted (as shipped)

## Context

Forensic readers historically expose `Read + Seek`. That shape carries a hidden cursor
(mutable position state), which forces `&mut self` on every read, defeats sharing across
threads, and makes two concurrent readers of one image race on the seek offset. It also
admits writes by construction — `Write`/`Seek` on the same handle can mutate evidence.

## Decision

The byte-source contract is `ImageSource`: `fn read_at(&self, offset: u64, buf: &mut [u8])`.
The offset is an *argument*, not stored state. The trait is `Send + Sync` and read-only —
no method can mutate the underlying image.

## Consequences

- One `Arc<dyn ImageSource>` (`DynSource`) is freely shared across threads; parallel walks
  need no per-reader clone or lock at the API boundary.
- Evidence is read-only *structurally*, not by policy — there is no write method to misuse.
- Readers built on a native `Read + Seek` handle (e.g. a `File`) adapt via a small
  poison-recovering `Mutex` wrapper that serializes seek+read under the lock while keeping
  the outward contract cursorless. That cost is paid once, at the adapter, not in the
  contract.
- `read_exact_at` and default `extents()`/`view()` live as provided methods, so a minimal
  impl is just `len` + `read_at`.
