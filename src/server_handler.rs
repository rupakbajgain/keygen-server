use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroize;
use listenfd::ListenFd;

use std::sync::Mutex;
use std::collections::HashMap;

use crate::request::Request;
use crate::response::Response;
use crate::secret_vault::SecretVault;
use crate::wrapped_key::WrappedKey;
use crate::paths::get_master_key_path;
use crate::archive_key::{ArchiveKey,ARCHIVE_KEY_SIZE,ARCHIVE_ID_SIZE};


#[derive(Eq, Hash, PartialEq)]
pub struct KeyId(pub [u8; ARCHIVE_ID_SIZE]);

pub struct ArchiveKeyID(pub [u8; ARCHIVE_KEY_SIZE]);

impl Zeroize for ArchiveKeyID {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

struct ServerState {
    pub vault: Arc<SecretVault>,
    pub wrapped_key: WrappedKey,
    pub archive_keys: Mutex<HashMap<KeyId, ArchiveKeyID>>,
}

impl Drop for ServerState {
    fn drop(&mut self) {
        if let Ok(mut map) = self.archive_keys.lock() {
            for value in map.values_mut() {
                value.zeroize();
            }
        }
    }
}

impl ServerState {
    pub fn new(vault: Arc<SecretVault>, wrapped_key: WrappedKey) -> Self {
        Self {
            vault,
            wrapped_key,
            archive_keys: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert_archive_key(&self, id: [u8; 16], key_bytes: [u8; 32]) {
        let mut map = self.archive_keys.lock().expect("Mutex poisoned");
        map.insert(KeyId(id), ArchiveKeyID(key_bytes));
    }
}

/// Start the Unix socket server
pub fn start_socket_server(socket_path: &str) -> std::io::Result<()> {
    // 1. Load the wrapped key once before starting the listener
    let master_key_path = get_master_key_path();
    if !master_key_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Master key file not found. Please run 'keygen' first.",
        ));
    }
    let wrapped_key = WrappedKey::load_from_disk(&master_key_path)?;

    // 2. get socket
    let mut listenfd = ListenFd::from_env();

    let listener = if let Some(l) = listenfd.take_unix_listener(0)? {
        // CASE A: systemd handed us the socket
        println!("Using socket passed by systemd: {}", socket_path);
        l
    } else {
        // CASE B: Manual run (not started by systemd socket)
        println!("Manual start. Binding to: {}", socket_path);

        // Cleanup old socket file only if we are the ones creating it
        if fs::metadata(socket_path).is_ok() {
            fs::remove_file(socket_path)?;
        }

        let l = UnixListener::bind(socket_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
        }
        l
    };

    // 3. Initialize state with the pre-loaded key
    let state = Arc::new(ServerState::new(SecretVault::new(),wrapped_key));

    // Replace the hex::encode line with this:
    let id_hex: String = state.wrapped_key.id.iter()
    .take(8)
    .map(|b| format!("{:02x}", b))
    .collect();

    println!("Loaded Master Key ID: {}", id_hex);

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let state_clone = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(e) = handle_client(s, state_clone) {
                        eprintln!("Client session error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("Incoming connection error: {:?}", e),
        }
    }
    Ok(())
}

fn handle_client(mut stream: UnixStream, state: Arc<ServerState>) -> std::io::Result<()> {
    loop {
        let frame = match read_frame(&mut stream)? {
            Some(f) => f,
            None => break,
        };

        let req = Request::from_binary(&frame);
        let resp = handle_request(req, &state);

        let encoded_res = resp.to_binary();
        write_frame(&mut stream, &encoded_res)?;
    }
    Ok(())
}

fn handle_request(req: Request, state: &ServerState) -> Response {
    match req {
        Request::Ping => Response::Ok { msg: "pong".into() },

        // No more disk I/O here
        Request::GetID => Response::Data {
            data: state.wrapped_key.id.to_vec()
        },

        Request::Pass { password } => {
            match state.wrapped_key.decrypt(&password) {
                Ok(master_key) => {
                    let ttl = Duration::from_secs(3600); // 1 hour session

                    // 1. Vault the Master Key
                    if let Err(e) = state.vault.set_key_from_zeroizing(master_key, ttl) {
                        return Response::Error { msg: format!("Vault error: {}", e) };
                    }

                    // 2. Proactively derive the "Virtual Archive" key (ID 0x00...)
                    // We need to re-get the key from the vault or use the zeroizing result
                    if let Some(master_plaintext) = state.vault.get_key() {
                        let virtual_id = [0u8; 16];
                        let arch_path = "/virtual-archive/"; // Your specified path

                        match crate::derived_keys::derive_key(
                            &master_plaintext,
                            crate::derived_keys::KeyPurpose::ArchiveHeader,
                            Some(arch_path)
                        ) {
                            Ok(derived_bytes) => {
                                // 3. Insert into the session map so QuickDerive can find it later
                                state.insert_archive_key(virtual_id, derived_bytes);

                                Response::Ok {
                                    msg: "Master unlocked. Virtual archive (0x00...) initialized.".into()
                                }
                            }
                            Err(e) => {
                                // If derivation fails, we still unlocked, but warn about virtual init
                                Response::Ok {
                                    msg: format!("Master unlocked, but virtual init failed: {}", e)
                                }
                            }
                        }
                    } else {
                        Response::Error { msg: "Vault state error after unlock".into() }
                    }
                }
                Err(_) => Response::Error { msg: "Incorrect master password".into() },
            }
        }

        Request::ArchiveGen => {
            match ArchiveKey::generate() {
                Ok(arch_key) => {
                    // 1. Get Master Key from Vault to wrap it immediately for the user
                    let master_plaintext = match state.vault.get_key() {
                        Some(k) => k,
                        None => return Response::Error { msg: "Vault locked".into() },
                    };

                    match arch_key.wrap(&master_plaintext) {
                        Ok(wrapped_key) => {
                            let id_hex = arch_key.id;

                            // 2. Store in memory (keyed by ID)
                            state.archive_keys.lock().unwrap().insert(KeyId(id_hex), ArchiveKeyID(arch_key.key));

                            // 3. Send back the fields for the external program
                            Response::ArchiveFields {
                                wrapped_key,
                                nonce: arch_key.nonce,
                                archive_id: arch_key.id,
                            }
                        }
                        Err(e) => Response::Error { msg: e.to_string() },
                    }
                }
                Err(e) => Response::Error { msg: e.to_string() },
            }
        }

        Request::ArchiveLoad {wrapped_key, archive_id, nonce } => {
            // 1. Check if ID already exists in memory to skip decryption
            {
                let map = state.archive_keys.lock().expect("Mutex poisoned");
                if map.contains_key(&KeyId(archive_id)) {
                    return Response::Ok {
                        msg: "Archive key already loaded".into()
                    };
                }
            } // MutexGuard is dropped here
            // Else  Get Master Key from Vault
            let master_plaintext = match state.vault.get_key() {
                Some(k) => k,
                None => return Response::Error { msg: "Vault locked. Unlock with master password first.".into() },
            };

            // 2. Unwrap the archive key using the master key
            match ArchiveKey::unwrap(&wrapped_key, &master_plaintext, archive_id, nonce) {
                Ok(arch_key) => {
                    // 3. Store the decrypted key in memory state
                    state.insert_archive_key(arch_key.id, arch_key.key);

                    Response::Ok {
                        msg: format!("Archive key loaded successfully")
                    }
                }
                Err(e) => Response::Error { msg: format!("Failed to load archive key: {}", e) },
            }
        }

        Request::DerivedKey { archive_id, purpose, path } => {
            let archive_keys = state.archive_keys.lock().unwrap();

            let key_id = KeyId(archive_id);

            let Some(archive_key_wrapper) = archive_keys.get(&key_id) else {
                return Response::Error {
                    msg: format!("Archive key not loaded for ID: {:?}", archive_id)
                };
            };

            let path_opt = if path.is_empty() { None } else { Some(path.as_str()) };

            // 2. Pass the inner bytes of the ArchiveKeyID/Zeroizing wrapper
            // Usually archive_key_wrapper is a Zeroizing<Vec<u8>> or similar
            match crate::derived_keys::derive_key(&archive_key_wrapper.0, purpose, path_opt) {
                Ok(derived_bytes) => {
                    Response::Key {
                        key: derived_bytes.to_vec(),
                    }
                }
                Err(e) => {
                    Response::Error { msg: format!("Derivation failed: {}", e) }
                }
            }
        }

        Request::Unknown => Response::Error { msg: "Unknown command".into() },
    }
}

// --- Framing Helpers ---

fn read_frame(stream: &mut UnixStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_be_bytes(len_buf) as usize;

    // Safety limit: 10MB
    if len > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Frame too large"));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_frame(stream: &mut UnixStream, data: &[u8]) -> std::io::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(data)?;
    stream.flush()
}
