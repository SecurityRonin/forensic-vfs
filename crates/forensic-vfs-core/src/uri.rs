//! The lossless canonical URI form of a [`crate::PathSpec`] and its parser.
//!
//! `PathSpec` to `String` to `PathSpec` is byte-for-byte lossless (every reserved
//! byte, including `/` and `%`, is percent-encoded), so a spec pasted from a
//! report re-opens exactly. Round-trip is a test-enforced invariant.
//!
//! Grammar: `fvfs:` then layers joined by `|`. Each layer is `tag:body`; every
//! value byte outside the unreserved set `[A-Za-z0-9._-]` is `%HH`, so the
//! structural delimiters `| : , /` only ever appear as structure.

#[cfg(test)]
mod tests {
    use crate::crypto::CryptoScheme;
    use crate::fs::{FileId, FsKind, StreamId};
    use crate::pathspec::{Guid, Layer, NodeAddr, PathSpec, SnapshotRef};
    use crate::registry::ContainerFormat;
    use crate::volume::VolumeScheme;

    fn roundtrip(spec: &PathSpec) {
        let uri = spec.to_uri();
        let back = PathSpec::from_uri(&uri).expect("parse own output");
        assert_eq!(&back, spec, "round-trip changed the spec; uri={uri}");
    }

    #[test]
    fn rich_chain_round_trips() {
        let spec = PathSpec::os("/evidence/DC01.E01")
            .push(Layer::Container {
                format: ContainerFormat::Ewf,
            })
            .push(Layer::Volume {
                scheme: VolumeScheme::Gpt,
                index: 1,
                guid: Some(Guid([
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
                    0x54, 0x32, 0x10,
                ])),
            })
            .push(Layer::Fs {
                kind: FsKind::Ntfs,
                at: NodeAddr::Path(vec![
                    b"Windows".to_vec(),
                    b"System32".to_vec(),
                    b"config".to_vec(),
                    b"SYSTEM".to_vec(),
                ]),
            })
            .push(Layer::Stream {
                id: StreamId::Named(3),
            });
        roundtrip(&spec);
    }

    #[test]
    fn hostile_path_bytes_round_trip_losslessly() {
        // A component with the layer delimiter, the escape char, a slash, a
        // space, and a non-UTF-8 byte — all must survive.
        let nasty = b"a|b%c/d e\xff\x00z".to_vec();
        let spec = PathSpec::os("/img.raw").push(Layer::Fs {
            kind: FsKind::Ext,
            at: NodeAddr::Path(vec![nasty.clone(), b"plain".to_vec()]),
        });
        let uri = spec.to_uri();
        // No raw delimiter leaked from the value into the structure.
        assert!(!uri.contains("a|b"), "delimiter leaked: {uri}");
        roundtrip(&spec);
    }

    #[test]
    fn every_layer_kind_round_trips() {
        roundtrip(&PathSpec::os("/x").push(Layer::Range {
            start: 512,
            len: 1_048_576,
        }));
        roundtrip(&PathSpec::os("/x").push(Layer::Crypto {
            scheme: CryptoScheme::Bitlocker,
        }));
        roundtrip(&PathSpec::os("/x").push(Layer::Snapshot {
            store: SnapshotRef::VssStore(4),
        }));
        roundtrip(&PathSpec::os("/x").push(Layer::Snapshot {
            store: SnapshotRef::ApfsXid(9_000_000),
        }));
        // Every FileId variant.
        for id in [
            FileId::NtfsRef { entry: 5, seq: 2 },
            FileId::ExtInode { ino: 12, gen: 7 },
            FileId::ApfsOid { oid: 99, xid: 3 },
            FileId::FatDirEntry {
                cluster: 8,
                index: 1,
            },
            FileId::IsoExtent { block: 40 },
            FileId::Opaque(123),
        ] {
            roundtrip(&PathSpec::os("/x").push(Layer::Fs {
                kind: FsKind::Apfs,
                at: NodeAddr::File(id),
            }));
        }
        // Both (id + observed path).
        roundtrip(&PathSpec::os("/x").push(Layer::Fs {
            kind: FsKind::Ntfs,
            at: NodeAddr::Both {
                path: vec![b"Users".to_vec(), b"beth".to_vec()],
                id: FileId::NtfsRef { entry: 91, seq: 1 },
            },
        }));
        // Stream variants.
        for s in [
            StreamId::Default,
            StreamId::Named(7),
            StreamId::ResourceFork,
            StreamId::Xattr(2),
            StreamId::Slack,
        ] {
            roundtrip(&PathSpec::os("/x").push(Layer::Stream { id: s }));
        }
    }

    #[test]
    fn empty_path_round_trips() {
        roundtrip(&PathSpec::os("/x").push(Layer::Fs {
            kind: FsKind::Iso9660,
            at: NodeAddr::Path(vec![]),
        }));
    }

    #[test]
    fn from_uri_rejects_garbage() {
        assert!(PathSpec::from_uri("not-a-spec").is_err());
        assert!(PathSpec::from_uri("fvfs:").is_err());
        assert!(PathSpec::from_uri("fvfs:bogustag:x").is_err());
        assert!(PathSpec::from_uri("fvfs:range:notanumber").is_err());
    }

    #[test]
    fn human_display_is_readable_and_not_the_uri() {
        let spec = PathSpec::os("/evidence/DC01.E01")
            .push(Layer::Container {
                format: ContainerFormat::Ewf,
            })
            .push(Layer::Fs {
                kind: FsKind::Ntfs,
                at: NodeAddr::Path(vec![b"Windows".to_vec()]),
            });
        let human = format!("{spec}");
        assert!(human.contains("DC01.E01"), "human form: {human}");
        assert!(human.contains("Windows"), "human form: {human}");
        assert_ne!(human, spec.to_uri());
    }
}
