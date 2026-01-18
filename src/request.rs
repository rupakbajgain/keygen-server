use crate::req_res::ReqRes;

#[derive(Debug, PartialEq)]
pub enum Request {
    Pass { password: String },
    GetID,
    Ping,
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

        match command.as_str() {
            "pass" => {
                let password = String::from_utf8(rr.fields.get("password").cloned().unwrap_or_default())
                .unwrap_or_default();
                Request::Pass { password }
            }
            "get_master_id" => Request::GetID,
            "ping" => Request::Ping,
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
