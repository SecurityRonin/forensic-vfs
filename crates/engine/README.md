# forensic-vfs-engine

The registry + resolver over the [`forensic-vfs`](https://crates.io/crates/forensic-vfs)
contracts: **one `Vfs::open(path)` that detects a piece of evidence's
container/volume/filesystem stack and mounts a read-only `dyn FileSystem`.** This
is the ORCHESTRATION crate — the one place that depends *down* on every fleet
reader, so callers (a CLI, a FUSE mount, a correlation engine) never branch per
format.

```rust,ignore
let vfs = Vfs::new();
let evidence = vfs.open(Path::new("disk.E01"))?;   // EWF → MBR → NTFS, one call
if let Some(fs) = evidence.fs {
    let id = fs.lookup(fs.root(), b"file1.txt")?.unwrap();
    // read_at, read_dir, extents, meta … all through `dyn FileSystem`
}
```

## How it resolves

`Vfs::open` resolves the base byte source (EWF opens *by path* — it's
multi-segment — else a raw `FileSource`), then **recurses**: sniff a source; if a
`FileSystemProbe` recognizes it, mount; else if a `VolumeSystemProbe` recognizes
it, descend each volume (a `SubRange` of the parent) and resolve that. Depth-capped
against nesting bombs; an unrecognized source is a clean `fs: None`, a missing base
is a loud error.

## Status — work in progress

Registered today: EWF container (by path), **MBR** volume system, **NTFS**
filesystem — validated end-to-end against real evidence (an NTFS-in-E01 and an
MBR-partitioned NTFS disk, with The Sleuth Kit as the oracle). `publish = false`:
it path-depends the `vfs`-feature branches of `ewf`/`ntfs-core` until those
publish. Next: GPT, more filesystems (ext4/FAT), single-stream container decoders
(VMDK/VHD/QCOW2), and the crypto layer.
