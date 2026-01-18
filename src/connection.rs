use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use crate::request::Request;
use crate::response::Response;
use crate::req_res::ReqRes;
use std::path::Path;

/// Read a single frame with 4-byte length prefix and convert to Request
pub fn read_request(stream: &mut UnixStream) -> std::io::Result<Option<Request>> {
    match read_frame(stream)? {
        Some(payload) => Ok(Some(Request::from_binary(&payload))),
        None => Ok(None),
    }
}

/// Convert Response to binary and write as a framed message
pub fn send_response(stream: &mut UnixStream, response: &Response) -> std::io::Result<()> {
    let binary = response.to_binary();
    write_frame(stream, &binary)
}

/// Internal helper: Read raw bytes with 4-byte length prefix
fn read_frame(stream: &mut UnixStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {},
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_be_bytes(len_buf) as usize;

    // Safety check: 10MB limit
    if len > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }

    let mut buf = vec![0u8; len];
    match stream.read_exact(&mut buf) {
        Ok(()) => Ok(Some(buf)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

/// Internal helper: Write raw bytes with 4-byte length prefix
fn write_frame(stream: &mut UnixStream, data: &[u8]) -> std::io::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(data)?;
    stream.flush()?; // Ensure data is sent over the socket
    Ok(())
}

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
