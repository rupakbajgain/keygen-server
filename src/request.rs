use crate::req_res::ReqRes;
use crate::derived_keys::KeyPurpose;
use std::str::FromStr;

pub enum Request {
    Pass { password: String },
    GetID,
    Ping,
    ArchiveGen,
    ArchiveLoad { wrapped_key: Vec<u8>, nonce: [u8; 12], archive_id: [u8; 16] },
    DerivedKey { archive_id: [u8; 16], purpose: KeyPurpose, path: String },
    Unknown,
}

impl Request {
    /// Creates a Request enum by parsing raw binary data
    pub fn from_binary(bytes: &[u8]) -> Self {
        let rr = match ReqRes::from_binary(bytes) {
            Ok(data) => data,
            Err(_) => return Request::Unknown,
        };

        let command = rr.fields.get("command")
        .and_then(|b| String::from_utf8(b.clone()).ok())
        .unwrap_or_default();

        match command.to_lowercase().as_str() {
            "pass" => {
                let password = String::from_utf8(rr.fields.get("password").cloned().unwrap_or_default())
                .unwrap_or_default();
                Request::Pass { password }
            }
            "master.get_id" => Request::GetID,
            "ping" => Request::Ping,
            "archive.generate" => Request::ArchiveGen,
            "archive.load" => {
                let Some(wrapped_key) = rr.fields.get("wrapped_key")
                .and_then(|b| b.as_slice().try_into().ok()) else {
                    return Request::Unknown;
                };

                // Extract Nonce: try to convert slice to [u8; 12], else return early
                let Some(nonce) = rr.fields.get("nonce")
                .and_then(|b| b.as_slice().try_into().ok()) else {
                    return Request::Unknown;
                };

                // Extract Archive ID: try to convert slice to [u8; 16], else return early
                let Some(archive_id) = rr.fields.get("archive_id")
                .and_then(|b| b.as_slice().try_into().ok()) else {
                    return Request::Unknown;
                };

                Request::ArchiveLoad {
                    wrapped_key,
                    nonce,
                    archive_id
                }
            },
            "derived.key" => {
                let Some(archive_id) = rr.fields.get("archive_id")
                .and_then(|b| b.as_slice().try_into().ok()) else {
                    return Request::Unknown;
                };

                let purpose_str = rr.fields.get("purpose")
                .and_then(|b| String::from_utf8(b.clone()).ok())
                .unwrap_or_default();

                // Assuming KeyPurpose implements FromStr or a similar mapping
                let Ok(purpose) = KeyPurpose::from_str(&purpose_str) else {
                    return Request::Unknown;
                };

                let path = rr.fields.get("path")
                .and_then(|b| String::from_utf8(b.clone()).ok())
                .unwrap_or_default();

                Request::DerivedKey { archive_id, purpose, path }
            }
            _ => Request::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_logic() {
        // 1. Generate binary using the helper
        let mut rr = ReqRes::new();
        rr.fields.insert("command".to_string(), "pass".into());
        rr.fields.insert("password".to_string(), "my_secure_password".into());

        let binary = rr.to_binary();

        // 2. Parse it back using the Request enum logic
        let req = Request::from_binary(&binary);

        if let Request::Pass { password } = req {
            assert_eq!(password, "my_secure_password");
        } else {
            panic!("Failed to parse Pass request");
        }
    }
}
