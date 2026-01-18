mod req_res;
mod wrapped_key;
mod secret_vault;
mod request;
mod response;
mod connection;
mod server_handler;
mod paths;
mod archive_key;
//mod fingerprint;

use std::env;
use std::io::Result;
use wrapped_key::WrappedKey;
use paths::{get_master_key_path, get_socket_path};
use server_handler::start_socket_server;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Start server if no args
    if args.len() == 1 {
        let socket_path = get_socket_path();
        println!("Starting socket server at {:?}", socket_path);
        return start_socket_server(&socket_path.to_string_lossy());
    }

    match args[1].to_lowercase().as_str() {
        "keygen" => {
            WrappedKey::generate(&get_master_key_path())?;
        }
        "pass" => {
            let pwd = rpassword::prompt_password("Enter Master Password: ")
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            // Use our connection helper to send the request
            connection::send_pass_request(&get_socket_path(), &pwd)?;
        }
        _ => {
            eprintln!("Usage: [no args] | keygen | pass");
            std::process::exit(1);
        }
    }
    Ok(())
}
