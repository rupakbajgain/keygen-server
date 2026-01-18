use ring::aead;

//#[derive(Clone)]
pub struct WrappedKey {
    pub salt: [u8; 16],
    pub nonce: [u8; aead::NONCE_LEN],
    pub ciphertext: Vec<u8>, // Contains the encrypted key + the 16-byte AEAD tag
}

impl WrappedKey {
    /// Creates a new WrappedKey from a raw byte buffer (e.g., from a file)
    pub fn from_bytes(mut bytes: Vec<u8>) -> std::io::Result<Self> {
        if bytes.len() < 16 + aead::NONCE_LEN + 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Key file is too small or corrupted",
            ));
        }

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; aead::NONCE_LEN];

        // Split the vector into its components
        // 1. Extract Salt
        let remaining = bytes.split_off(16);
        salt.copy_from_slice(&bytes);

        // 2. Extract Nonce
        let mut remaining = remaining;
        let ciphertext = remaining.split_off(aead::NONCE_LEN);
        nonce.copy_from_slice(&remaining);

        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }
}
