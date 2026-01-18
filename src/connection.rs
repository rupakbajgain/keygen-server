use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use crate::response::Response;
use crate::req_res::ReqRes;
use std::path::Path;

pub fn send_pass_request(socket_path: &Path, password: &str) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(socket_path)?;

    // 1. Manually build the ReqRes map for the "Pass" command
    let mut rr = ReqRes::new();
    rr.fields.insert("command".into(), "pass".into());
    rr.fields.insert("password".into(), password.as_bytes().to_vec());

    // 2. Convert to binary using your existing ReqRes::to_binary()
    let bin_req = rr.to_binary();

    // 3. Write frame: [4-byte length prefix][binary data]
    let len_prefix = (bin_req.len() as u32).to_be_bytes();
    stream.write_all(&len_prefix)?;
    stream.write_all(&bin_req)?;
    stream.flush()?;

    // 4. Read response frame length
    let mut resp_len_buf = [0u8; 4];
    stream.read_exact(&mut resp_len_buf)?;
    let resp_len = u32::from_be_bytes(resp_len_buf) as usize;

    // 5. Read response body
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf)?;

    // 6. Decode using your Response enum's from_binary
    let resp = Response::from_binary(&resp_buf)
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    match resp {
        Response::Ok { msg } => println!("Success: {}", msg),
        Response::Error { msg } => eprintln!("Error: {}", msg),
        _ => eprintln!("Unexpected response variant from server"),
    }

    Ok(())
}
