mod req_res;
mod wrapped_key;
mod secret_vault;
mod request;
mod response;
mod connection;
mod server_handler;
mod paths;

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
            let key_path = get_master_key_path();
            WrappedKey::generate(&key_path)?;
            println!("Key generated successfully at {:?}", key_path);
        }
        "pass" => {
            println!("Use the client tool to send the password to the daemon.");
        }
        _ => {
            eprintln!("Usage: [no args] | keygen | pass");
            std::process::exit(1);
        }
    }
    Ok(())
}
