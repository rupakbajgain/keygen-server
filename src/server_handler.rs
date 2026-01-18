use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

use crate::request::Request;
use crate::response::Response;
use crate::secret_vault::SecretVault;

struct ServerState {
    pub vault: Arc<SecretVault>,
}

/// Start the Unix socket server
pub fn start_socket_server(socket_path: &str) -> std::io::Result<()> {
    // Cleanup old socket file
    if fs::metadata(socket_path).is_ok() {
        fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    // Set socket permissions to 0600 (owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    }

    let state = Arc::new(ServerState {
        vault: SecretVault::new(),
    });

    println!("Listening on: {:?}", socket_path);

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let state_clone = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(e) = handle_client(s, state_clone) {
                        eprintln!("Client disconnected with error: {}", e);
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
        // 1. Read Frame (4-byte length + binary body)
        let frame = match read_frame(&mut stream)? {
            Some(f) => f,
            None => break, // Clean EOF
        };

        // 2. Parse binary into Request Enum
        let req = Request::from_binary(&frame);

        // 3. Process the command
        let resp = handle_request(req, &state);

        // 4. Convert Response Enum to binary and write frame
        let encoded_res = resp.to_binary();
        write_frame(&mut stream, &encoded_res)?;
    }
    Ok(())
}

fn handle_request(req: Request, state: &ServerState) -> Response {
    match req {
        Request::Ping => Response::Ok { msg: "pong".into() },

        Request::Pass { password } => {
            // Logic for unlocking the vault
            if password == "password" {
                let secret_key = b"highly-sensitive-master-key".to_vec();

                // vault.set_key handles random XOR mask and TTL reaper thread
                match state.vault.set_key(secret_key, Duration::from_secs(3600)) {
                    Ok(_) => Response::Ok { msg: "Vault unlocked".into() },
                    Err(e) => Response::Error { msg: format!("Security error: {}", e) },
                }
            } else {
                Response::Error { msg: "Invalid password".into() }
            }
        },

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
