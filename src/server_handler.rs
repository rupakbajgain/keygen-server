use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

use crate::request::Request;
use crate::response::Response;
use crate::secret_vault::SecretVault;
use crate::wrapped_key::WrappedKey;
use crate::paths::get_master_key_path;

struct ServerState {
    pub vault: Arc<SecretVault>,
    // Load this once at startup
    pub wrapped_key: WrappedKey,
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

    // 2. Cleanup old socket file
    if fs::metadata(socket_path).is_ok() {
        fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    }

    // 3. Initialize state with the pre-loaded key
    let state = Arc::new(ServerState {
        vault: SecretVault::new(),
                         wrapped_key,
    });

    println!("Listening on: {:?}", socket_path);

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
            // Use the pre-loaded key from state
            match state.wrapped_key.decrypt(&password) {
                Ok(master_key) => {
                    let ttl = Duration::from_secs(600);
                    match state.vault.set_key_from_zeroizing(master_key, ttl) {
                        Ok(_) => Response::Ok { msg: "Master key unlocked and vaulted".into() },
                        Err(e) => Response::Error { msg: format!("Vault error: {}", e) },
                    }
                }
                Err(_) => Response::Error { msg: "Incorrect master password".into() },
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
