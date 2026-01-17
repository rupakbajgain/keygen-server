mod wrapped_key;

use wrapped_key::WrappedKey;
use ring::{pbkdf2, rand::{SystemRandom, SecureRandom}, aead};
use std::env;
use std::fs::{self, File};
use std::path::Path;
use std::io::{Read, Write, Error, ErrorKind};
use std::num::NonZeroU32;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::os::unix::fs::PermissionsExt;
use zeroize::Zeroizing;
const ITERATIONS: u32 = 100_000;

fn get_master_key_path() -> PathBuf {
    let mut path = home::home_dir().expect("Could not find home directory");
    path.push(".base0");
    // Ensure the hidden directory exists
    if !path.exists() {
        fs::create_dir_all(&path).expect("Failed to create ~/.base0 directory");
    }
    path.push("master.key");
    path
}

fn get_socket_path() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    let base_path = PathBuf::from(format!("/run/user/{}/mfs", uid));
    if !base_path.exists() {
        fs::create_dir_all(&base_path).expect("Failed to create mfs directory");
    }
    base_path.join("keyserver.socket")
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        println!("Master key verified. Starting socket server...");
        return start_socket_server();
    }
    match args[1].to_lowercase().as_str() {
        "keygen" => {
            generate_key()?;
            println!("Key generated successfully.");
        }
        "pass" => {
            // Here you would implement your logic to send
            // the password to the running daemon
            println!("Sending password to server...");
            //send_password_to_server()?;
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Usage: [no args] | keygen | pass");
            std::process::exit(1);
        }
    }
    eprintln!("Usage: [no args] | keygen | pass");
    Ok(())
}

fn generate_key() -> std::io::Result<()> {
    let key_path = get_master_key_path();

    // 1. Check if key already exists
    if Path::new(&key_path).exists() {
        println!("Master key already exists at: {:?}", key_path);
        return Ok(()); // Return early
    }

    let rng = SystemRandom::new();

    // 1. Get Password and derive the "Wrapping Key"
    let pwd = rpassword::prompt_password("Enter Master Password: ")
    .map_err(|e| Error::new(ErrorKind::Other, e))?;
    let pwd2 = rpassword::prompt_password("Enter Password Again: ")
    .map_err(|e| Error::new(ErrorKind::Other, e))?;

    let trimmed_pwd = pwd.trim();
    if trimmed_pwd != pwd2.trim() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Passwords do not match",
        ));
    }

    let mut salt = [0u8; 16];
    rng.fill(&mut salt).map_err(|_| Error::new(ErrorKind::Other, "RNG failed"))?;

    let mut wrapping_key_bytes = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(ITERATIONS).unwrap(),
                   &salt,
                   trimmed_pwd.as_bytes(),
                   &mut wrapping_key_bytes,
    );

    // 2. Generate the "Actual Key" (The one that will encrypt your data)
    let mut actual_key = [0u8; 32];
    rng.fill(&mut actual_key).map_err(|_| Error::new(ErrorKind::Other, "RNG failed"))?;

    // 3. Encrypt the Actual Key using AES-256-GCM
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &wrapping_key_bytes)
    .map_err(|_| Error::new(ErrorKind::Other, "Invalid key length"))?;
    let sealing_key = aead::LessSafeKey::new(unbound_key);

    // Generate a random Nonce (96 bits / 12 bytes for AES-GCM)
    let mut nonce_bytes = [0u8; aead::NONCE_LEN];
    rng.fill(&mut nonce_bytes).map_err(|_| Error::new(ErrorKind::Other, "RNG failed"))?;
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    // Ring encrypts in-place. We need a buffer that holds the key + the tag (16 bytes)
    let mut in_out = actual_key.to_vec();
    sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
    .map_err(|_| Error::new(ErrorKind::Other, "Encryption failed"))?;

    // 4. Save to disk: [Salt] + [Nonce] + [EncryptedKey + Tag]
    let mut f = File::create(&key_path)?;

    // Set permissions to 0600 (owner read/write only)
    let mut perms = f.metadata()?.permissions();
    perms.set_mode(0o600);
    f.set_permissions(perms)?;

    f.write_all(&salt)?;        // 16 bytes
    f.write_all(&nonce_bytes)?; // 12 bytes
    f.write_all(&in_out)?;      // 32 bytes (key) + 16 bytes (tag) = 48 bytes

    println!("Success: Master key created.");
    Ok(())
}

fn load_key_file() -> std::io::Result<WrappedKey> {
    let key_path = get_master_key_path();
    let bytes = std::fs::read(&key_path)?;
    WrappedKey::from_bytes(bytes)
}

fn decrypt_master_key(password: &str, mut wrapped: WrappedKey) -> std::io::Result<Zeroizing<Vec<u8>>> {
    // 1. Derive the Wrapping Key (used to decrypt the master key)
    // We wrap this in Zeroizing too so the intermediate key is wiped!
    let mut wrapping_key_bytes = Zeroizing::new([0u8; 32]);

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(ITERATIONS).unwrap(),
                   &wrapped.salt,
                   password.trim().as_bytes(),
                   wrapping_key_bytes.as_mut(),
    );

    // 2. Setup AES-GCM
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, wrapping_key_bytes.as_ref())
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Crypto failure"))?;
    let opening_key = aead::LessSafeKey::new(unbound_key);

    let nonce_obj = aead::Nonce::assume_unique_for_key(wrapped.nonce);

    // 3. Decrypt in-place
    let decrypted_slice = opening_key
    .open_in_place(nonce_obj, aead::Aad::empty(), &mut wrapped.ciphertext)
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Incorrect password"))?;

    // 4. Return as Zeroizing.
    // This ensures that when the caller is done, the RAM is wiped.
    Ok(Zeroizing::new(decrypted_slice.to_vec()))
}

fn start_socket_server() -> std::io::Result<()> {
    let path = get_socket_path();
    if path.exists() { fs::remove_file(&path)?; }

    let listener = UnixListener::bind(&path)?;
    let key_file = load_key_file()?;

    println!("Listening on: {:?}", path);

    for stream in listener.incoming() {
        let mut s = stream?;
        let mut buf = [0; 1024];
        let n = s.read(&mut buf)?;
        println!("Received: {}", String::from_utf8_lossy(&buf[..n]));
        s.write_all(b"Handshake OK")?;
    }
    Ok(())
}
