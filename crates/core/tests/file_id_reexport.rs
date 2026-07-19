//! ADR 0009 re-export identity: `forensic_vfs::FileId` IS
//! `forensicnomicon_core::FileId` (the type moved down to the zero-dep KNOWLEDGE
//! leaf; forensic-vfs re-exports it so every existing `forensic_vfs::FileId`
//! import keeps working verbatim). This test compiles only when the two paths
//! name the *same* type — while forensic-vfs still defines its own local enum,
//! `same()` is a type mismatch and this fails to build (RED).

#[test]
fn file_id_is_the_reexported_fn_core_type() {
    // Identity coercion: only type-checks if the two paths are the same type.
    fn same(x: forensicnomicon_core::FileId) -> forensic_vfs::FileId {
        x
    }

    let core = forensicnomicon_core::FileId::NtfsRef { entry: 7, seq: 3 };
    let vfs: forensic_vfs::FileId = same(core);
    assert_eq!(vfs, forensic_vfs::FileId::NtfsRef { entry: 7, seq: 3 });
}
