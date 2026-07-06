//! The lossless canonical URI form of a [`crate::PathSpec`] and its parser.
//!
//! `PathSpec` to `String` to `PathSpec` is byte-for-byte lossless (every reserved
//! byte, including `/` and `%`, is percent-encoded), so a spec pasted from a
//! report re-opens exactly. Round-trip is a test-enforced invariant.
//!
//! Grammar: `fvfs:` then layers joined by `|`. Each layer is `tag:body`; every
//! value byte outside the unreserved set `[A-Za-z0-9._-]` is `%HH`, so the
//! structural delimiters `| : , /` only ever appear as structure.

use core::fmt;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::crypto::CryptoScheme;
use crate::error::{SmallHex, VfsError, VfsResult};
use crate::fs::{FileId, FsKind, StreamId};
use crate::pathspec::{Guid, Layer, NodeAddr, PathSpec, SnapshotRef};
use crate::registry::ContainerFormat;
use crate::volume::VolumeScheme;

const SCHEME: &str = "fvfs:";
const LAYER_SEP: char = '|';

fn err(detail: &str, ctx: &str) -> VfsError {
    VfsError::Decode {
        layer: "pathspec-uri",
        offset: 0,
        detail: detail.to_string(),
        bytes: SmallHex::new(ctx.as_bytes()),
    }
}

// --- percent-encoding: unreserved = [A-Za-z0-9._-]; everything else is %HH ---

fn pct_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            s.push(b as char);
        } else {
            let _ = write!(s, "%{b:02X}");
        }
    }
    s
}

fn pct_decode(s: &str) -> VfsResult<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hex = b
                .get(i + 1..i + 3)
                .ok_or_else(|| err("truncated percent escape", s))?;
            let hex = core::str::from_utf8(hex).map_err(|_| err("non-ascii percent escape", s))?;
            let v = u8::from_str_radix(hex, 16).map_err(|_| err("bad percent hex", s))?;
            out.push(v);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    Ok(out)
}

#[cfg(unix)]
fn path_to_bytes(p: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    p.as_os_str().as_bytes().to_vec()
}
#[cfg(not(unix))]
fn path_to_bytes(p: &Path) -> Vec<u8> {
    p.to_string_lossy().into_owned().into_bytes()
}
#[cfg(unix)]
fn bytes_to_path(b: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(b))
}
#[cfg(not(unix))]
fn bytes_to_path(b: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(b).into_owned())
}

// --- token vocab (round-trips 1:1; #[non_exhaustive] handled by _ => error) ---

fn container_token(f: ContainerFormat) -> &'static str {
    match f {
        ContainerFormat::Ewf => "ewf",
        ContainerFormat::Vmdk => "vmdk",
        ContainerFormat::Vhdx => "vhdx",
        ContainerFormat::Vhd => "vhd",
        ContainerFormat::Qcow2 => "qcow2",
        ContainerFormat::Dmg => "dmg",
        ContainerFormat::Aff4 => "aff4",
        ContainerFormat::Ad1 => "ad1",
        ContainerFormat::Dar => "dar",
        ContainerFormat::Raw => "raw",
        ContainerFormat::Auto => "auto",
    }
}
fn parse_container(t: &str, ctx: &str) -> VfsResult<ContainerFormat> {
    Ok(match t {
        "ewf" => ContainerFormat::Ewf,
        "vmdk" => ContainerFormat::Vmdk,
        "vhdx" => ContainerFormat::Vhdx,
        "vhd" => ContainerFormat::Vhd,
        "qcow2" => ContainerFormat::Qcow2,
        "dmg" => ContainerFormat::Dmg,
        "aff4" => ContainerFormat::Aff4,
        "ad1" => ContainerFormat::Ad1,
        "dar" => ContainerFormat::Dar,
        "raw" => ContainerFormat::Raw,
        "auto" => ContainerFormat::Auto,
        _ => return Err(err("unknown container format", ctx)),
    })
}
fn volume_token(s: VolumeScheme) -> &'static str {
    match s {
        VolumeScheme::Mbr => "mbr",
        VolumeScheme::Gpt => "gpt",
        VolumeScheme::Apm => "apm",
        VolumeScheme::Vss => "vss",
        VolumeScheme::ApfsContainer => "apfscontainer",
        VolumeScheme::Lvm => "lvm",
    }
}
fn parse_volume_scheme(t: &str, ctx: &str) -> VfsResult<VolumeScheme> {
    Ok(match t {
        "mbr" => VolumeScheme::Mbr,
        "gpt" => VolumeScheme::Gpt,
        "apm" => VolumeScheme::Apm,
        "vss" => VolumeScheme::Vss,
        "apfscontainer" => VolumeScheme::ApfsContainer,
        "lvm" => VolumeScheme::Lvm,
        _ => return Err(err("unknown volume scheme", ctx)),
    })
}
fn crypto_token(s: CryptoScheme) -> &'static str {
    match s {
        CryptoScheme::Bitlocker => "bitlocker",
        CryptoScheme::Luks1 => "luks1",
        CryptoScheme::Luks2 => "luks2",
        CryptoScheme::FileVault => "filevault",
        CryptoScheme::ApfsEncrypted => "apfsencrypted",
    }
}
fn parse_crypto(t: &str, ctx: &str) -> VfsResult<CryptoScheme> {
    Ok(match t {
        "bitlocker" => CryptoScheme::Bitlocker,
        "luks1" => CryptoScheme::Luks1,
        "luks2" => CryptoScheme::Luks2,
        "filevault" => CryptoScheme::FileVault,
        "apfsencrypted" => CryptoScheme::ApfsEncrypted,
        _ => return Err(err("unknown crypto scheme", ctx)),
    })
}
fn fs_token(k: FsKind) -> &'static str {
    match k {
        FsKind::Ntfs => "ntfs",
        FsKind::Ext => "ext",
        FsKind::HfsPlus => "hfsplus",
        FsKind::Apfs => "apfs",
        FsKind::Iso9660 => "iso9660",
        FsKind::Udf => "udf",
        FsKind::Fat => "fat",
        FsKind::ExFat => "exfat",
        FsKind::Other => "other",
    }
}
fn parse_fs_kind(t: &str, ctx: &str) -> VfsResult<FsKind> {
    Ok(match t {
        "ntfs" => FsKind::Ntfs,
        "ext" => FsKind::Ext,
        "hfsplus" => FsKind::HfsPlus,
        "apfs" => FsKind::Apfs,
        "iso9660" => FsKind::Iso9660,
        "udf" => FsKind::Udf,
        "fat" => FsKind::Fat,
        "exfat" => FsKind::ExFat,
        "other" => FsKind::Other,
        _ => return Err(err("unknown filesystem kind", ctx)),
    })
}

fn u64_field(t: &str, ctx: &str) -> VfsResult<u64> {
    t.parse::<u64>().map_err(|_| err("expected integer", ctx))
}
fn u32_field(t: &str, ctx: &str) -> VfsResult<u32> {
    t.parse::<u32>().map_err(|_| err("expected u32", ctx))
}
fn usize_field(t: &str, ctx: &str) -> VfsResult<usize> {
    t.parse::<usize>().map_err(|_| err("expected index", ctx))
}

fn guid_hex(g: Guid) -> String {
    let mut s = String::with_capacity(32);
    for b in g.0 {
        let _ = write!(s, "{b:02x}");
    }
    s
}
fn parse_guid(t: &str, ctx: &str) -> VfsResult<Guid> {
    if t.len() != 32 {
        return Err(err("guid must be 32 hex chars", ctx));
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = t
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| err("bad guid", ctx))?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| err("bad guid hex", ctx))?;
    }
    Ok(Guid(out))
}

// FileId: '.'-separated token; no '/' or ',' so it nests inside a NodeAddr.
fn file_id_token(id: FileId) -> String {
    match id {
        FileId::NtfsRef { entry, seq } => format!("ntfsref.{entry}.{seq}"),
        FileId::ExtInode { ino, gen } => format!("extinode.{ino}.{gen}"),
        FileId::ApfsOid { oid, xid } => format!("apfsoid.{oid}.{xid}"),
        FileId::FatDirEntry { cluster, index } => format!("fatdirentry.{cluster}.{index}"),
        FileId::IsoExtent { block } => format!("isoextent.{block}"),
        FileId::Opaque(n) => format!("opaque.{n}"),
    }
}
fn parse_file_id(t: &str, ctx: &str) -> VfsResult<FileId> {
    let mut it = t.split('.');
    let head = it.next().ok_or_else(|| err("empty file id", ctx))?;
    let mut num = |name: &str| -> VfsResult<u64> {
        it.next()
            .ok_or_else(|| err(name, ctx))
            .and_then(|s| u64_field(s, ctx))
    };
    Ok(match head {
        "ntfsref" => FileId::NtfsRef {
            entry: num("entry")?,
            seq: num("seq")? as u16,
        },
        "extinode" => FileId::ExtInode {
            ino: num("ino")?,
            gen: num("gen")? as u32,
        },
        "apfsoid" => FileId::ApfsOid {
            oid: num("oid")?,
            xid: num("xid")?,
        },
        "fatdirentry" => FileId::FatDirEntry {
            cluster: num("cluster")? as u32,
            index: num("index")? as u16,
        },
        "isoextent" => FileId::IsoExtent {
            block: num("block")? as u32,
        },
        "opaque" => FileId::Opaque(num("n")?),
        _ => return Err(err("unknown file id kind", ctx)),
    })
}

fn stream_token(s: StreamId) -> String {
    match s {
        StreamId::Default => "default".to_string(),
        StreamId::Named(n) => format!("named.{n}"),
        StreamId::ResourceFork => "resourcefork".to_string(),
        StreamId::Xattr(n) => format!("xattr.{n}"),
        StreamId::Slack => "slack".to_string(),
    }
}
fn parse_stream(t: &str, ctx: &str) -> VfsResult<StreamId> {
    let mut it = t.split('.');
    let head = it.next().unwrap_or("");
    Ok(match head {
        "default" => StreamId::Default,
        "resourcefork" => StreamId::ResourceFork,
        "slack" => StreamId::Slack,
        "named" => StreamId::Named(u32_field(it.next().unwrap_or(""), ctx)? as u16),
        "xattr" => StreamId::Xattr(u32_field(it.next().unwrap_or(""), ctx)? as u16),
        _ => return Err(err("unknown stream id", ctx)),
    })
}

fn node_addr_encode(a: &NodeAddr) -> String {
    let comps = |cs: &[Vec<u8>]| -> String {
        let mut s = String::new();
        for c in cs {
            s.push('/');
            s.push_str(&pct_encode(c));
        }
        s
    };
    match a {
        NodeAddr::Path(cs) => format!("p{}", comps(cs)),
        NodeAddr::File(id) => format!("f/{}", file_id_token(*id)),
        NodeAddr::Both { path, id } => format!("b/{}{}", file_id_token(*id), comps(path)),
    }
}
fn parse_node_addr(t: &str, ctx: &str) -> VfsResult<NodeAddr> {
    let decode_comps = |rest: &str| -> VfsResult<Vec<Vec<u8>>> {
        if rest.is_empty() {
            return Ok(Vec::new());
        }
        // `rest` begins with '/'.
        let body = rest.strip_prefix('/').unwrap_or(rest);
        body.split('/').map(pct_decode).collect()
    };
    let (tag, rest) = t.split_at(t.chars().next().map_or(0, char::len_utf8));
    match tag {
        "p" => Ok(NodeAddr::Path(decode_comps(rest)?)),
        "f" => {
            let id = rest.strip_prefix('/').unwrap_or(rest);
            Ok(NodeAddr::File(parse_file_id(id, ctx)?))
        }
        "b" => {
            let rest = rest.strip_prefix('/').unwrap_or(rest);
            let mut parts = rest.splitn(2, '/');
            let id = parse_file_id(parts.next().unwrap_or(""), ctx)?;
            let path = match parts.next() {
                Some(p) => p
                    .split('/')
                    .map(pct_decode)
                    .collect::<VfsResult<Vec<_>>>()?,
                None => Vec::new(),
            };
            Ok(NodeAddr::Both { path, id })
        }
        _ => Err(err("unknown node address", ctx)),
    }
}

fn layer_encode(l: &Layer) -> String {
    match l {
        Layer::Os { path } => format!("os:{}", pct_encode(&path_to_bytes(path))),
        Layer::Range { start, len } => format!("range:{start},{len}"),
        Layer::Container { format } => format!("container:{}", container_token(*format)),
        Layer::Volume {
            scheme,
            index,
            guid,
        } => {
            let mut s = format!("volume:{},{index}", volume_token(*scheme));
            if let Some(g) = guid {
                let _ = write!(s, ",{}", guid_hex(*g));
            }
            s
        }
        Layer::Crypto { scheme } => format!("crypto:{}", crypto_token(*scheme)),
        Layer::Snapshot { store } => match store {
            SnapshotRef::VssStore(i) => format!("snapshot:vss,{i}"),
            SnapshotRef::ApfsXid(x) => format!("snapshot:apfs,{x}"),
        },
        Layer::Fs { kind, at } => format!("fs:{},{}", fs_token(*kind), node_addr_encode(at)),
        Layer::Stream { id } => format!("stream:{}", stream_token(*id)),
    }
}

fn layer_parse(s: &str) -> VfsResult<Layer> {
    let (tag, body) = s
        .split_once(':')
        .ok_or_else(|| err("layer missing tag", s))?;
    match tag {
        "os" => Ok(Layer::Os {
            path: bytes_to_path(&pct_decode(body)?),
        }),
        "range" => {
            let (a, b) = body
                .split_once(',')
                .ok_or_else(|| err("range needs start,len", s))?;
            Ok(Layer::Range {
                start: u64_field(a, s)?,
                len: u64_field(b, s)?,
            })
        }
        "container" => Ok(Layer::Container {
            format: parse_container(body, s)?,
        }),
        "volume" => {
            let mut it = body.split(',');
            let scheme = parse_volume_scheme(it.next().unwrap_or(""), s)?;
            let index = usize_field(it.next().ok_or_else(|| err("volume needs index", s))?, s)?;
            let guid = match it.next() {
                Some(g) => Some(parse_guid(g, s)?),
                None => None,
            };
            Ok(Layer::Volume {
                scheme,
                index,
                guid,
            })
        }
        "crypto" => Ok(Layer::Crypto {
            scheme: parse_crypto(body, s)?,
        }),
        "snapshot" => {
            let (kind, num) = body
                .split_once(',')
                .ok_or_else(|| err("snapshot needs kind,id", s))?;
            let store = match kind {
                "vss" => SnapshotRef::VssStore(usize_field(num, s)?),
                "apfs" => SnapshotRef::ApfsXid(u64_field(num, s)?),
                _ => return Err(err("unknown snapshot kind", s)),
            };
            Ok(Layer::Snapshot { store })
        }
        "fs" => {
            let (kind, at) = body
                .split_once(',')
                .ok_or_else(|| err("fs needs kind,addr", s))?;
            Ok(Layer::Fs {
                kind: parse_fs_kind(kind, s)?,
                at: parse_node_addr(at, s)?,
            })
        }
        "stream" => Ok(Layer::Stream {
            id: parse_stream(body, s)?,
        }),
        _ => Err(err("unknown layer tag", s)),
    }
}

impl PathSpec {
    /// The lossless canonical URI form — round-trips byte-for-byte through
    /// [`PathSpec::from_uri`].
    #[must_use]
    pub fn to_uri(&self) -> String {
        let mut s = String::from(SCHEME);
        let layers = self.layers();
        for (i, l) in layers.iter().enumerate() {
            if i > 0 {
                s.push(LAYER_SEP);
            }
            s.push_str(&layer_encode(l));
        }
        s
    }

    /// Parse a canonical URI produced by [`PathSpec::to_uri`]. Loud on any
    /// malformed input (carries the offending string).
    pub fn from_uri(s: &str) -> VfsResult<PathSpec> {
        let rest = s
            .strip_prefix(SCHEME)
            .ok_or_else(|| err("missing fvfs: scheme", s))?;
        let mut layers = rest.split(LAYER_SEP);
        let first = layers.next().ok_or_else(|| err("empty spec", s))?;
        let mut spec = PathSpec::root(layer_parse(first)?);
        for l in layers {
            spec = spec.push(layer_parse(l)?);
        }
        Ok(spec)
    }
}

/// Lossy, human-readable form — readable, explicitly non-parseable (use
/// [`PathSpec::to_uri`] for a form that round-trips).
impl fmt::Display for PathSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let comps = |cs: &[Vec<u8>]| {
            cs.iter()
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect::<Vec<_>>()
                .join("/")
        };
        let mut first = true;
        for l in self.layers() {
            if !first {
                write!(f, " | ")?;
            }
            first = false;
            match l {
                Layer::Os { path } => write!(f, "os:{}", path.display())?,
                Layer::Range { start, len } => write!(f, "range[{start}+{len}]")?,
                Layer::Container { format } => write!(f, "{}", container_token(*format))?,
                Layer::Volume { scheme, index, .. } => {
                    write!(f, "{}#{index}", volume_token(*scheme))?;
                }
                Layer::Crypto { scheme } => write!(f, "{}", crypto_token(*scheme))?,
                Layer::Snapshot { store } => match store {
                    SnapshotRef::VssStore(i) => write!(f, "vss#{i}")?,
                    SnapshotRef::ApfsXid(x) => write!(f, "apfs@{x}")?,
                },
                Layer::Fs { kind, at } => match at {
                    NodeAddr::Path(cs) | NodeAddr::Both { path: cs, .. } => {
                        write!(f, "{}:/{}", fs_token(*kind), comps(cs))?;
                    }
                    NodeAddr::File(id) => write!(f, "{}#{}", fs_token(*kind), file_id_token(*id))?,
                },
                Layer::Stream { id } => write!(f, ":{}", stream_token(*id))?,
            }
        }
        Ok(())
    }
}

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
