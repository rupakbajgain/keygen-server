use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use crate::request::Request;
use crate::response::Response;
use crate::req_res::ReqRes;

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

pub fn send_pass(stream: &mut UnixStream, password: &str) -> std::io::Result<Response> {
    // 1. Prepare the request map
    let mut rr = ReqRes::new();
    rr.fields.insert("command".to_string(), "pass".into());
    rr.fields.insert("password".to_string(), password.as_bytes().to_vec());

    // 2. Serialize and write using the frame helper
    let binary_req = rr.to_binary();
    write_frame(stream, &binary_req)?;

    // 3. Read the response frame
    // We expect a response, so None (EOF) is an error here
    let resp_bytes = read_frame(stream)?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Connection closed before response")
    })?;

    // 4. Convert binary to Response Enum
    Response::from_binary(&resp_bytes)
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
