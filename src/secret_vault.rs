use std::sync::{Arc, Mutex, Condvar};
use std::time::{Instant, Duration};
use zeroize::{Zeroizing, Zeroize};
use ring::rand::{SecureRandom, SystemRandom};

struct VaultState {
    // Masked data: (Original Key ^ Mask)
    masked_data: Option<Zeroizing<Vec<u8>>>,
    // Random bits used to obfuscate the data
    mask: Zeroizing<Vec<u8>>,
    expires_at: Instant,
}

pub struct SecretVault {
    state: Mutex<VaultState>,
    cvar: Condvar,
    rng: SystemRandom,
}

/// Helper to prevent memory from being swapped to disk
fn strict_lock(ptr: *const u8, len: usize) -> std::io::Result<()> {
    if len == 0 { return Ok(()); }
    unsafe {
        if libc::mlock(ptr as *const libc::c_void, len) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

impl SecretVault {
    pub fn new() -> Arc<Self> {
        let vault = Arc::new(Self {
            state: Mutex::new(VaultState {
                masked_data: None,
                mask: Zeroizing::new(Vec::new()),
                              expires_at: Instant::now(),
            }),
            cvar: Condvar::new(),
                             rng: SystemRandom::new(),
        });

        let v_clone = Arc::clone(&vault);
        std::thread::Builder::new()
        .name("vault-reaper".to_string())
        .spawn(move || {
            let mut state = v_clone.state.lock().unwrap();
            loop {
                match &state.masked_data {
                    None => state = v_clone.cvar.wait(state).unwrap(),
               Some(_) => {
                   let now = Instant::now();
                   if now >= state.expires_at {
                       state.masked_data = None;
                       state.mask.zeroize();
                       println!("Security: Vault TTL expired. Secret zeroed.");
                   } else {
                       let ttl = state.expires_at - now;
                       let result = v_clone.cvar.wait_timeout(state, ttl).unwrap();
                       state = result.0;
                   }
               }
                }
            }
        })
        .expect("Failed to spawn reaper thread");

        vault
    }

    /// Sets the key while maintaining Zeroize protection during the handover.
    pub fn set_key_from_zeroizing(&self, mut key: Zeroizing<Vec<u8>>, duration: Duration) -> std::io::Result<()> {
        let mut state = self.state.lock().unwrap();

        let mut mask_bytes = vec![0u8; key.len()];
        self.rng.fill(&mut mask_bytes).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "Random number generation failed")
        })?;

        // Lock both the secret and the mask in RAM
        strict_lock(key.as_ptr(), key.len())?;
        strict_lock(mask_bytes.as_ptr(), mask_bytes.len())?;

        // Obfuscate via XOR
        for i in 0..key.len() {
            key[i] ^= mask_bytes[i];
        }

        state.masked_data = Some(key);
        state.mask = Zeroizing::new(mask_bytes);
        state.expires_at = Instant::now() + duration;

        self.cvar.notify_one();
        Ok(())
    }

    /// Reconstructs the key into a temporary Zeroizing buffer.
    pub fn get_key(&self) -> Option<Zeroizing<Vec<u8>>> {
        let state = self.state.lock().unwrap();

        if let Some(ref masked) = state.masked_data {
            if Instant::now() < state.expires_at {
                let mut original = vec![0u8; masked.len()];

                // Lock the buffer where the plaintext will be reconstructed
                strict_lock(original.as_ptr(), original.len())
                .expect("SECURITY CRITICAL: Failed to lock plaintext memory buffer");

                for i in 0..masked.len() {
                    original[i] = masked[i] ^ state.mask[i];
                }

                return Some(Zeroizing::new(original));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_set_and_get_key() {
        let vault = SecretVault::new();
        let secret_raw = b"my_ultra_secure_key".to_vec();

        // Wrap in Zeroizing to match the method signature
        let secret = Zeroizing::new(secret_raw.clone());

        vault.set_key_from_zeroizing(secret, Duration::from_secs(10)).unwrap();

        let retrieved = vault.get_key().expect("Key should exist");
        assert_eq!(&*retrieved, &secret_raw);
    }

    #[test]
    fn test_key_obfuscation() {
        let vault = SecretVault::new();
        let secret_raw = vec![0xAA, 0xAA, 0xAA, 0xAA];
        let secret = Zeroizing::new(secret_raw.clone());

        vault.set_key_from_zeroizing(secret, Duration::from_secs(10)).unwrap();

        let state = vault.state.lock().unwrap();
        let masked = state.masked_data.as_ref().unwrap();

        // Verify the internal memory is XORed and not plaintext
        assert_ne!(masked.as_slice(), secret_raw.as_slice());
    }

    #[test]
    fn test_expiration() {
        let vault = SecretVault::new();
        let secret = Zeroizing::new(b"short-lived".to_vec());

        // Set a very short TTL
        vault.set_key_from_zeroizing(secret, Duration::from_millis(50)).unwrap();

        // Should be available immediately
        assert!(vault.get_key().is_some());

        // Wait for reaper/expiration logic to kick in
        thread::sleep(Duration::from_millis(150));
        assert!(vault.get_key().is_none(), "Key should have expired and been zeroed");
    }

    #[test]
    fn test_concurrent_access() {
        let vault = SecretVault::new();
        let secret_raw = b"concurrent_key".to_vec();
        let secret = Zeroizing::new(secret_raw.clone());

        vault.set_key_from_zeroizing(secret, Duration::from_secs(60)).unwrap();

        let mut handles = vec![];
        for _ in 0..10 {
            let v = Arc::clone(&vault);
            let s_expected = secret_raw.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let retrieved = v.get_key().expect("Vault should still hold the key");
                    assert_eq!(&*retrieved, &s_expected);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
