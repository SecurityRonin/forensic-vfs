# 0003 — Layer stack composed through `DynSource`

**Status:** Accepted (revised 2026-07-18 — the archive layer is promoted to a first-class
transform, so the model is now five kinds; the layer traits are unified to the `*Open`
family, with the code rename riding the 0.4 fleet cut per ADR 0008).

## Context

Real evidence is layered: a filesystem inside an encrypted volume inside a partition
inside a compressed container inside an archive (NTFS ⊂ BitLocker ⊂ GPT-partition ⊂ E01 ⊂
`.zip`/`.gz`). If each layer exposes a different API, the stack is bespoke glue and each
joint is a defect site.

## Decision

**Five transform kinds — container · archive · volume · encryption · filesystem — composed
by return type** rather than by knowing each other's concrete type. Each is one `*Open`
trait, named for its primary `open()` method; the two methods are its two steps — `probe()`
recognizes (dispatch), `open()` peels/decodes:

- `ImageSource` — flat byte image (the universal currency every layer speaks).
- `ContainerOpen::open -> DynSource` — a container format (E01/VMDK/VHDX/QCOW2/DMG/AFF4/AD1)
  yields a raw byte source.
- `ArchiveOpen::open -> ArchiveContents` — an archive layer yields either
  `Stream(DynSource)` (1→1: a bare gz/bz2 wrapper, re-entering resolution like a decode) or
  `Members(Vec<Member>)` (1→N: tar/zip/7z, each member re-entering resolution). This is the
  archive layer promoted to a first-class peer (ADR 0008).
- `VolumeSystemOpen::open_volume(index) -> DynSource` — a partition scheme yields a windowed
  sub-source.
- `EncryptionOpen::open(creds) -> DynSource` — an encryption layer yields a decrypted
  sub-source.
- `FileSystemOpen` — parses over any `ImageSource`.

Because each layer's `open` returns a `DynSource` (`Arc<dyn ImageSource>`) — or, for an
archive, `DynSource`s reached through `ArchiveContents` — the output of any layer is the
input of the next. The concrete `SubRange` adapter windows a parent source for the volume
case.

## Consequences

- Arbitrary stacks compose without a combinatorial matrix of adapters: N containers ×
  A archive formats × M volume schemes × K encryption layers × J filesystems is
  N+A+M+K+J impls, not N·A·M·K·J.
- A layer is testable in isolation against any `ImageSource`, including an in-memory one.
- The vertical layers (`VolumeSystemOpen`, `EncryptionOpen`) currently have zero leaf impls;
  the composition model is proven in engine tests, but no shipped pipeline yet walks a
  partitioned-and-encrypted image end to end. This is the primary remaining work
  (see PRD §7).
