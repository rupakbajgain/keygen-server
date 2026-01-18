use ring::hkdf;
use std::str::FromStr;
use std::fmt;

pub const KEY_SIZE: usize = 32;

pub type Result<T> = std::result::Result<T, String>;

//#[derive(Debug, PartialEq, Clone, Copy)]
pub enum KeyPurpose {
    ArchiveHeader,
    ArchiveChunk,
    Metadata,
    Signing,
}

impl FromStr for KeyPurpose {
    // Change this to String to match your custom Result alias
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "archive_header" | "header" => Ok(KeyPurpose::ArchiveHeader),
            "archive_chunk"  | "chunk"  => Ok(KeyPurpose::ArchiveChunk),
            "metadata"                  => Ok(KeyPurpose::Metadata),
            "signing"        | "sign"   => Ok(KeyPurpose::Signing),
            _ => Err(format!("'{}' is not a valid KeyPurpose", s)),
        }
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            KeyPurpose::ArchiveHeader => "archive_header",
            KeyPurpose::ArchiveChunk  => "archive_chunk",
            KeyPurpose::Metadata      => "metadata",
            KeyPurpose::Signing       => "signing",
        };
        write!(f, "{}", s)
    }
}

/// 1. Derive a specific 32-byte key
pub fn derive_key(
    base_key: &[u8],
    purpose: KeyPurpose,
    path: Option<&str>,
) -> Result<[u8; KEY_SIZE]> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"derived-key");
    let prk = salt.extract(base_key);

    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"purpose:");
    info.extend_from_slice(purpose.to_string().as_ref());

    if let Some(p) = path {
        info.push(0);
        info.extend_from_slice(p.as_bytes());
    }

    let mut okm = [0u8; KEY_SIZE];
    prk.expand(&[&info], hkdf::HKDF_SHA256)
    .map_err(|_| "HKDF expansion failed".to_string())?
    .fill(&mut okm)
    .map_err(|_| "Key fill failed".to_string())?;

    Ok(okm)
}
