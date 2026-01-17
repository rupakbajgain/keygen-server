use std::sync::{Arc, Mutex, Condvar};
use std::time::{Instant, Duration};
use zeroize::Zeroizing;

struct VaultState {
    // Zeroizing<Vec<u8>> ensures bits are wiped on drop/removal
    data: Option<Zeroizing<Vec<u8>>>,
    expires_at: Instant,
}

pub struct SecretVault {
    state: Mutex<VaultState>,
    cvar: Condvar,
}

impl SecretVault {
    pub fn new() -> Arc<Self> {
        let vault = Arc::new(Self {
            state: Mutex::new(VaultState {
                data: None,
                expires_at: Instant::now(),
            }),
            cvar: Condvar::new(),
        });

        let v_clone = Arc::clone(&vault);
        std::thread::spawn(move || {
            let mut state = v_clone.state.lock().unwrap();
            loop {
                match &state.data {
                    None => {
                        // Sleep forever until set_key notifies
                        state = v_clone.cvar.wait(state).unwrap();
                    }
                    Some(_) => {
                        let now = Instant::now();
                        if now >= state.expires_at {
                            // Key expires: .take() pulls it out,
                            // and it is zeroed immediately as it goes out of scope
                            let expired_key = state.data.take();
                            drop(expired_key);
                            println!("Security: Master key zeroed and destroyed.");
                        } else {
                            // Sleep for the remaining TTL
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

    pub fn set_key(&self, key: Vec<u8>, duration: Duration) {
        let mut state = self.state.lock().unwrap();

        // If an old key exists, taking it out and letting it drop triggers zeroize
        state.data = Some(Zeroizing::new(key));
        state.expires_at = Instant::now() + duration;

        // Wake the reaper thread to handle the new deadline
        self.cvar.notify_one();
    }

    pub fn get_key(&self) -> Option<Vec<u8>> {
        let state = self.state.lock().unwrap();
        if let Some(ref key) = state.data {
            if Instant::now() < state.expires_at {
                // We return a plain Vec here for use,
                // but the master copy remains wrapped in Zeroizing
                return Some(key.to_vec());
            }
        }
        None
    }

    pub fn clear(&self) {
        let mut state = self.state.lock().unwrap();
        state.data = None; // Automatic wipe happens here
        self.cvar.notify_one();
    }
}
