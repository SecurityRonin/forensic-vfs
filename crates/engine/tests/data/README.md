# tests/data — forensic-vfs-engine fixtures

Both are minted from the TSK-validated `SampleTinyNtfsVolume` NTFS volume
(Joakim Schicht's `LogFileParser` sample, MIT; the raw `.dd` lives in
`ntfs-forensic/tests/data/SampleTinyNtfsVolume.zip`). Oracle for all content:
The Sleuth Kit (`file1.txt` = MFT record 37, 408 bytes, "Just some bogus").

| File | What | Mint |
|------|------|------|
| `ntfs_sample.E01` | bare 7 MiB NTFS volume, acquired | `ewfacquire -u -t ntfs_sample -f encase6 -c deflate:best partition.dd` (MD5 data `e4e9578a…`) |
| `partitioned_ntfs.E01` | 8 MiB MBR disk, one NTFS partition (type 0x07 @ LBA 2048), acquired | hand-built MBR + `dd` the volume at 1 MiB, then `ewfacquire` (MD5 data `b2f1cc81…`) |

The `partitioned_ntfs.dd` MBR was written in Python: partition entry at offset
446 (type 0x07, start LBA 2048, size 14336 sectors), signature 0x55AA at 510,
the NTFS volume copied to offset `2048*512`.

## ext4

`ext4.img` is a byte-for-byte copy of `ext4fs-forensic`'s TSK-validated
`minimal.img` (MD5 `966b3e52d95cb84679a973f43fd3702e`; provenance in
[`ext4fs-forensic/tests/data/README.md`](https://github.com/SecurityRonin/ext4fs-forensic)) —
a 4 MiB `mkfs.ext4` image (4096-byte blocks, no partition table) containing
`hello.txt` ("Hello, ext4!"). Oracle: The Sleuth Kit — `fls`/`istat`/`icat`
report `hello.txt` = **inode 13**, 12 bytes, direct block 9; used by
`open_ext4.rs` to prove the engine detects and mounts a bare ext4 volume.
