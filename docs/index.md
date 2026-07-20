# forensic-vfs

The KNOWLEDGE-leaf contract crate of the universal forensic VFS. It defines one
read-only, positioned-read byte edge — `ImageSource` — that every disk, container,
and filesystem reader in the fleet implements, so a whole evidence stack composes
as a single `Arc<dyn ImageSource>` that many workers read in parallel and no code
path can write.

## What it defines

- **`ImageSource`** — `read_at(&self, offset, buf)`, no cursor, no write method.
  Parallel-safe by construction; read-only in the type system.
- **Adapters** — `FileSource` (positioned OS reads), `SubRange` (a byte window
  that is itself an `ImageSource`), `SourceCursor` (a `Read + Seek` bridge).
- **The five layer-open traits** — `ContainerOpen`, `ArchiveOpen`,
  `VolumeSystemOpen`, `EncryptionOpen`, `FileSystemOpen`, each with the same
  `probe()` (recognize) + `open()` (peel) shape. A mounted `FileSystem` exposes
  `&self` navigation with owned `Send` streams; `FileId` (filesystem-specific
  identity), `FsMeta` (per-timestamp source/resolution provenance and the
  name/metadata allocation split), and `FsKind` (open newtype).
- **`Locator`** — the recursive locator, with a lossless canonical URI and a
  lossy human form; credentials stay out of the serialized address.
- **`Openers`** — the compiled-in probe dispatch table the engine fills; the
  sibling `forensic-vfs-resolver` walks it via `SourceOpen` to peel a whole stack.

## Design properties

- **Read-only by construction.** The byte-source trait has no write method;
  immutability is a type property, not a documented promise.
- **`&self` positioned-read parallel core.** One shared stack, lock-free hot path.
- **True leaf.** Base dependencies are `thiserror` (+ optional `serde`); the
  forensicnomicon findings bridge is a non-default feature, so a bare reader
  inherits neither.
- **Panic-free.** `unsafe_code = forbid`; bounded readers; fuzzed; 100% covered.

## Where it fits

`forensic-vfs` is the contract leaf of the universal forensic VFS. See
[Architecture](architecture.md) for the layered model and the crate topology, and
[Validation](validation.md) for the evidence behind the correctness claims.
