# 0003 — Four-layer stack composed through `DynSource`

**Status:** Accepted (as shipped)

## Context

Real evidence is layered: a filesystem inside an encrypted volume inside a partition
inside a compressed container (NTFS ⊂ BitLocker ⊂ GPT-partition ⊂ E01). If each layer
exposes a different API, the stack is bespoke glue and each joint is a defect site.

## Decision

Four contracts, composed by return type rather than by knowing each other's concrete
type:

- `ImageSource` — flat byte image (the universal currency).
- `VolumeSystem::open_volume(index) -> DynSource` — a partition scheme yields a windowed
  sub-source.
- `CryptoLayer::open(creds) -> DynSource` — an encryption layer yields a decrypted
  sub-source.
- `FileSystem` — parses over any `ImageSource`.

Because `open_volume` and `open` both return `DynSource` (`Arc<dyn ImageSource>`), the
output of any layer is the input of the next. The concrete `SubRange` adapter windows a
parent source for the volume case.

## Consequences

- Arbitrary stacks compose without a combinatorial matrix of adapters: N containers × M
  volume schemes × K crypto layers × J filesystems is N+M+K+J impls, not N·M·K·J.
- A layer is testable in isolation against any `ImageSource`, including an in-memory one.
- The two vertical layers (`VolumeSystem`, `CryptoLayer`) currently have zero leaf impls;
  the composition model is proven in engine tests, but no shipped pipeline yet walks a
  partitioned-and-encrypted image end to end. This is the primary remaining work
  (see PRD §7).
