use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

pub const ARCHIVE_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const ARCHIVE_ID_SIZE: usize = 16;

// Define a local Result alias for convenience
pub type Result<T> = std::result::Result<T, String>;

pub struct ArchiveKey {
    pub id: [u8; ARCHIVE_ID_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub key: [u8; ARCHIVE_KEY_SIZE],
}

impl Drop for ArchiveKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ArchiveKey {
    /// Command: ArchiveGen logic
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut id = [0u8; ARCHIVE_ID_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];
        let mut key = [0u8; ARCHIVE_KEY_SIZE];

        rng.fill(&mut id).map_err(|_| "Key generation failed: Could not generate ID".to_string())?;
        rng.fill(&mut nonce).map_err(|_| "Key generation failed: Could not generate nonce".to_string())?;
        rng.fill(&mut key).map_err(|_| "Key generation failed: Could not generate key material".to_string())?;

        Ok(Self { id, nonce, key })
    }

    /// Prepares the data for the external program
    pub fn wrap(&self, master_bytes: &[u8]) -> Result<Vec<u8>> {
        let unbound = UnboundKey::new(&AES_256_GCM, master_bytes)
        .map_err(|e| format!("Master key error: {}", e))?;

        let sealing_key = LessSafeKey::new(unbound);

        let mut data = self.key.to_vec();
        let nonce = Nonce::assume_unique_for_key(self.nonce);

        sealing_key
        .seal_in_place_append_tag(nonce, Aad::from(self.id), &mut data)
        .map_err(|_| "Encryption failed during wrapping".to_string())?;

        Ok(data)
    }

    /// Command: ArchiveLoad logic
    pub fn unwrap(
        wrapped: &[u8],
        master_bytes: &[u8],
        id: [u8; ARCHIVE_ID_SIZE],
        nonce: [u8; NONCE_SIZE],
    ) -> Result<Self> {
        let unbound = UnboundKey::new(&AES_256_GCM, master_bytes)
        .map_err(|e| format!("Master key error: {}", e))?;

        let opening_key = LessSafeKey::new(unbound);

        let mut buf = wrapped.to_vec();
        let ring_nonce = Nonce::assume_unique_for_key(nonce);

        let decrypted = opening_key
        .open_in_place(ring_nonce, Aad::from(id), &mut buf)
        .map_err(|_| "Authentication failed: Key or ID is incorrect".to_string())?;

        let mut key = [0u8; ARCHIVE_KEY_SIZE];
        key.copy_from_slice(decrypted);

        Ok(Self { id, nonce, key })
    }
}
