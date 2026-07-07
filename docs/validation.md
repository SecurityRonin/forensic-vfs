# Validation

`forensic-vfs` is a contract crate: it defines traits and one value-producing
codec (the `PathSpec` canonical URI). Correctness is established by the evidence
below, tiered honestly by *what confirms it*.

## The PathSpec URI codec — property-checked + fuzzed

The URI form is **our own format**, so no external tool decodes it — there is no
independent oracle to differential against. Correctness is therefore defined by a
*self-checking property*, not a hand-authored answer key:

> **Round-trip invariant.** For every `PathSpec`, `from_uri(to_uri(spec)) == spec`,
> byte-for-byte.

This is stronger than a fixture-with-expected-output (the LZNT1 trap): the test
does not assert "this input maps to that hand-written string"; it asserts the
encoder and decoder are mutual inverses, so a bug in either breaks the equality.
The property is checked two ways:

- **Unit + integration tests** exercise it across a rich chain, hostile path
  bytes (`|`, `%`, `/`, space, `0xFF`, `0x00`), every layer kind, every `FileId`
  and `StreamId` variant, empty paths, and the `Both`-with-empty-path branch.
- **Fuzzing** (`fuzz/fuzz_pathspec`) drives `from_uri` over arbitrary bytes and
  asserts the round-trip on everything it accepts — **15.7M executions, no panic
  and no round-trip violation**. `from_uri` rejects malformed input with a loud
  error carrying the offending string, never a panic.

This is the legitimate use of self-authored tests: a detection/serialization rule
whose correctness is defined by the rule plus a self-checking property, with no
external oracle possible. When the engine lands, a spec pasted from a report and
re-resolved on real evidence will be the end-to-end confirmation.

## Panic-free bounded readers — fuzzed

The `be_*`/`le_*` bounded integer readers are the panic-free foundation every
reader parses offsets through. `fuzz/fuzz_read` drives them over arbitrary
`(data, offset)` pairs including out-of-range and `usize::MAX` offsets —
**20.2M executions, no panic** — confirming the "0 on out-of-range, never panic"
contract.

## Object-safety of every trait

The design rests on `Arc<dyn ImageSource>`, `Arc<dyn FileSystem>`,
`Box<dyn VolumeSystem>`, and `Box<dyn CryptoLayer>` composing at runtime. A reader
double for each trait is driven through its trait object in
`tests/contracts.rs`; if any trait lost object-safety the crate would fail to
compile. The default forensic surface (`data_streams`, `hardlinks`, `slack`,
`findings`) and the credential/`NeedCredentials` path are exercised there too.

## Coverage

100% production line coverage (`cargo llvm-cov --all-features`), enforced in CI by
a `DA:n,0` gate that fails on any uncovered production line. Two lines carry
`// cov:unreachable`: the `get_mut(..want)` fallbacks in `SubRange` and
`SourceCursor`, provably unreachable because `want <= buf.len()` by the preceding
`min()`, kept as defence-in-depth.
