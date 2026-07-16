# Paper: A Universal Positioned-Read Contract for Forensic Evidence

Source for the paper describing the `forensic-vfs` universal reader contract
(`ImageSource` / `FileSystem`), the `safe-read` panic-free-by-construction parsing substrate, and
the positioned-read block-by-block decoding optimization over compressed images
(E01 chunks + scattered NTFS `$MFT` reads).

## Build

Requires XeLaTeX + BibTeX (TeX Live / MacTeX):

```
make          # -> universal-reader.pdf
make clean
```

## Evidence discipline

Empirical claims are tier-labelled (Table 1). The end-to-end NTFS-over-E01
composition is validated against The Sleuth Kit (Tier 1) but is a feature-gated
integration proof, not a shipped pipeline; the one-chunk memory figure is an
**analytical bound over a mechanism verified in code**, not yet a measured
resident-set benchmark of an `$MFT` walk. Both gaps are stated in the paper
(§Evaluation, §Discussion) rather than implied away.
