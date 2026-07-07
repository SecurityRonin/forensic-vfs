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
