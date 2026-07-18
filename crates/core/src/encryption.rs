//! [`EncryptionLayer`] — full-disk-encryption translation, a distinct layer between
//! volume and filesystem.
//!
//! BitLocker/LUKS/FileVault sit between a volume and its filesystem; the resolver
//! (in the engine) probes for them by on-disk header magic. Credentials are
//! supplied at resolve time through an injected [`CredentialSource`], never stored
//! in a [`crate::pathspec::PathSpec`], so a serialized address never leaks keys.

use crate::error::VfsResult;
use crate::source::DynSource;

/// The FDE scheme.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionScheme {
    Bitlocker,
    Luks1,
    Luks2,
    FileVault,
    ApfsEncrypted,
    /// VeraCrypt / TrueCrypt full-volume encryption (XTS, optional cipher cascade).
    VeraCrypt,
}

/// One credential offered to a encryption layer.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Credential {
    Password(String),
    /// BitLocker numeric recovery key or LUKS passphrase file contents.
    RecoveryKey(String),
    /// Raw key material (FVEK / volume master key).
    KeyBytes(Vec<u8>),
    /// A keyfile path the provider will read.
    KeyFile(std::path::PathBuf),
}

/// Supplies credentials at resolve time. Injected into the resolve call, kept out
/// of the serialized address, so a `PathSpec` is safe to persist and re-open
/// (the caller re-supplies credentials on re-open).
pub trait CredentialSource: Send + Sync {
    /// Offer credentials for a target (a volume GUID / label / scheme name). An
    /// empty slice means "none available" — the layer then errors
    /// [`crate::error::VfsError::NeedCredentials`] rather than guessing.
    fn credentials_for(&self, scheme: EncryptionScheme, target: &str) -> Vec<Credential>;
}

/// An encryption translation over one [`crate::ImageSource`]: consumes credentials +
/// ciphertext sectors, presents a decrypted [`DynSource`].
pub trait EncryptionLayer: Send + Sync {
    fn scheme(&self) -> EncryptionScheme;
    /// Present the decrypted volume. Errs `NeedCredentials` if keys are absent,
    /// `Decode` (loud, with the header bytes) on a bad key / unsupported cipher.
    fn open(&self, creds: &dyn CredentialSource) -> VfsResult<DynSource>;

    /// Findings raised while parsing the FDE header. Behind the `findings`
    /// feature so a bare reader does not inherit forensicnomicon.
    #[cfg(feature = "findings")]
    fn findings(&self) -> VfsResult<Vec<forensicnomicon::report::Finding>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::{Credential, CredentialSource, EncryptionScheme, NoCredentials};

    #[test]
    fn no_credentials_offers_nothing() {
        // The secure-by-default context: no keys for any scheme/target, so a
        // signature scheme surfaces NeedCredentials loud and a credential-attempt
        // scheme simply fails to decrypt (see ADR 0010).
        let creds = NoCredentials;
        let none: Vec<Credential> = creds.credentials_for(EncryptionScheme::Bitlocker, "vol-guid");
        assert!(none.is_empty());
        assert!(creds
            .credentials_for(EncryptionScheme::VeraCrypt, "")
            .is_empty());
    }
}
