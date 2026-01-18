use ring::{pbkdf2, rand::{SystemRandom, SecureRandom}, aead};
use std::fs::{self, File};
use std::io::{Write, Error, ErrorKind};
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use zeroize::Zeroizing;

const ITERATIONS: u32 = 100_000;

pub struct WrappedKey {
    pub salt: [u8; 16],
    pub nonce: [u8; aead::NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl WrappedKey {
    pub fn from_bytes(mut bytes: Vec<u8>) -> std::io::Result<Self> {
        if bytes.len() < 16 + aead::NONCE_LEN + 16 {
            return Err(Error::new(ErrorKind::InvalidData, "Key file too small"));
        }

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; aead::NONCE_LEN];

        let remaining = bytes.split_off(16);
        salt.copy_from_slice(&bytes);

        let mut remaining = remaining;
        let ciphertext = remaining.split_off(aead::NONCE_LEN);
        nonce.copy_from_slice(&remaining);

        Ok(Self { salt, nonce, ciphertext })
    }

    pub fn generate(path: &PathBuf) -> std::io::Result<()> {
        if path.exists() {
            println!("Master key already exists at: {:?}", path);
            return Ok(());
        }

        let rng = SystemRandom::new();
        let pwd = rpassword::prompt_password("Enter Master Password: ")
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
        let pwd2 = rpassword::prompt_password("Enter Password Again: ")
        .map_err(|e| Error::new(ErrorKind::Other, e))?;

        if pwd.trim() != pwd2.trim() {
            return Err(Error::new(ErrorKind::InvalidInput, "Passwords do not match"));
        }

        let mut salt = [0u8; 16];
        rng.fill(&mut salt).map_err(|_| Error::new(ErrorKind::Other, "RNG failed"))?;

        let mut wrapping_key_bytes = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(ITERATIONS).unwrap(),
                       &salt,
                       pwd.trim().as_bytes(),
                       &mut wrapping_key_bytes,
        );

        let mut actual_key = [0u8; 32];
        rng.fill(&mut actual_key).map_err(|_| Error::new(ErrorKind::Other, "RNG failed"))?;

        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &wrapping_key_bytes)
        .map_err(|_| Error::new(ErrorKind::Other, "Invalid key length"))?;
        let sealing_key = aead::LessSafeKey::new(unbound_key);

        let mut nonce_bytes = [0u8; aead::NONCE_LEN];
        rng.fill(&mut nonce_bytes).map_err(|_| Error::new(ErrorKind::Other, "RNG failed"))?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = actual_key.to_vec();
        sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| Error::new(ErrorKind::Other, "Encryption failed"))?;

        let mut f = File::create(path)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(&salt)?;
        f.write_all(&nonce_bytes)?;
        f.write_all(&in_out)?;

        Ok(())
    }

    pub fn decrypt(&self, password: &str) -> std::io::Result<Zeroizing<Vec<u8>>> {
        let mut wrapping_key_bytes = Zeroizing::new([0u8; 32]);
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(ITERATIONS).unwrap(),
                       &self.salt,
                       password.trim().as_bytes(),
                       wrapping_key_bytes.as_mut(),
        );

        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, wrapping_key_bytes.as_ref())
        .map_err(|_| Error::new(ErrorKind::Other, "Crypto failure"))?;
        let opening_key = aead::LessSafeKey::new(unbound_key);

        let nonce_obj = aead::Nonce::assume_unique_for_key(self.nonce);
        let mut ciphertext_copy = self.ciphertext.clone();

        let decrypted_slice = opening_key
        .open_in_place(nonce_obj, aead::Aad::empty(), &mut ciphertext_copy)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Incorrect password"))?;

        Ok(Zeroizing::new(decrypted_slice.to_vec()))
    }

    pub fn load_from_disk(path: &std::path::Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(bytes)
    }
}
