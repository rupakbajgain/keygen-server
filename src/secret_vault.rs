use std::sync::{Arc, Mutex, Condvar};
use std::time::{Instant, Duration};
use zeroize::{Zeroizing, Zeroize};
use ring::rand::{SecureRandom, SystemRandom};

struct VaultState {
    masked_data: Option<Zeroizing<Vec<u8>>>,
    mask: Zeroizing<Vec<u8>>,
    expires_at: Instant,
}

pub struct SecretVault {
    state: Mutex<VaultState>,
    cvar: Condvar,
    rng: SystemRandom, // Store the RNG generator
}

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
        std::thread::spawn(move || {
            let mut state = v_clone.state.lock().unwrap();
            loop {
                match &state.masked_data {
                    None => state = v_clone.cvar.wait(state).unwrap(),
                           Some(_) => {
                               let now = Instant::now();
                               if now >= state.expires_at {
                                   state.masked_data = None;
                                   state.mask.zeroize();
                                   println!("Security: Master key and mask zeroed.");
                               } else {
                                   let ttl = state.expires_at - now;
                                   let result = v_clone.cvar.wait_timeout(state, ttl).unwrap();
                                   state = result.0;
                               }
                           }
                }
            }
        });

        vault
    }

    pub fn set_key(&self, mut key: Vec<u8>, duration: Duration) -> std::io::Result<()> {
        let mut state = self.state.lock().unwrap();

        let mut mask_bytes = vec![0u8; key.len()];
        // Correct usage of Ring's SystemRandom
        self.rng.fill(&mut mask_bytes).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "Random number generation failed")
        })?;

        strict_lock(key.as_ptr(), key.len())?;
        strict_lock(mask_bytes.as_ptr(), mask_bytes.len())?;

        for i in 0..key.len() {
            key[i] ^= mask_bytes[i];
        }

        state.masked_data = Some(Zeroizing::new(key));
        state.mask = Zeroizing::new(mask_bytes);
        state.expires_at = Instant::now() + duration;

        self.cvar.notify_one();
        Ok(())
    }

    pub fn get_key(&self) -> Option<Zeroizing<Vec<u8>>> {
        let state = self.state.lock().unwrap();

        if let Some(ref masked) = state.masked_data {
            if Instant::now() < state.expires_at {
                let mut original = vec![0u8; masked.len()];

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
        let secret = b"my_ultra_secure_key".to_vec();

        vault.set_key(secret.clone(), Duration::from_secs(10)).unwrap();

        let retrieved = vault.get_key().expect("Key should exist");
        // FIX: Dereference to get the inner Vec
        assert_eq!(&*retrieved, &secret);
    }

    #[test]
    fn test_set_key_overwrites_old_one() {
        let vault = SecretVault::new();

        vault.set_key(b"first".to_vec(), Duration::from_secs(10)).unwrap();
        vault.set_key(b"second".to_vec(), Duration::from_secs(10)).unwrap();

        let retrieved = vault.get_key().unwrap();
        // FIX: Explicitly check as slice
        assert_eq!(retrieved.as_slice(), b"second");
    }

    #[test]
    fn test_concurrent_access() {
        let vault = SecretVault::new();
        let secret = b"concurrent_key".to_vec();
        vault.set_key(secret.clone(), Duration::from_secs(60)).unwrap();

        let mut handles = vec![];
        for _ in 0..10 {
            let v = Arc::clone(&vault);
            let s = secret.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let retrieved = v.get_key().unwrap();
                    // FIX: Dereference to inner Vec
                    assert_eq!(&*retrieved, &s);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
