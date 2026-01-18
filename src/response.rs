use crate::req_res::ReqRes;

#[derive(Debug, PartialEq)]
pub enum Response {
    Ok { msg: String },
    Data { data: Vec<u8> },
    Error { msg: String },
}

impl Response {
    /// Converts the Response enum into the binary format for the socket.
    /// Uses "status" as the primary key to distinguish between variants.
    pub fn to_binary(&self) -> Vec<u8> {
        let mut rr = ReqRes::new();

        match self {
            Response::Ok { msg } => {
                rr.fields.insert("status".into(), "ok".into());
                rr.fields.insert("msg".into(), msg.as_bytes().to_vec());
            }
            Response::Data { data } => {
                rr.fields.insert("status".into(), "data".into());
                rr.fields.insert("data".into(), data.clone());
            }
            Response::Error { msg } => {
                rr.fields.insert("status".into(), "error".into());
                rr.fields.insert("msg".into(), msg.as_bytes().to_vec());
            }
        }

        rr.to_binary()
    }

    /// (Optional) If you need the client to parse responses back:
    pub fn from_binary(bytes: &[u8]) -> Result<Self, String> {
        let rr = ReqRes::from_binary(bytes)?;
        let status = rr.fields.get("status")
        .and_then(|b| String::from_utf8(b.clone()).ok())
        .ok_or("Missing status")?;

        match status.as_str() {
            "ok" => {
                let msg = String::from_utf8(rr.fields.get("msg").cloned().unwrap_or_default())
                .unwrap_or_default();
                Ok(Response::Ok { msg })
            }
            "data" => {
                let data = rr.fields.get("data").cloned().unwrap_or_default();
                Ok(Response::Data { data })
            }
            "error" => {
                let msg = String::from_utf8(rr.fields.get("msg").cloned().unwrap_or_default())
                .unwrap_or_default();
                Ok(Response::Error { msg })
            }
            _ => Err(format!("Unknown status: {}", status)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok_response() {
        let res = Response::Ok { msg: "Success".into() };
        let bin = res.to_binary();
        let decoded = Response::from_binary(&bin).unwrap();
        assert_eq!(res, decoded);
    }

    #[test]
    fn test_data_response() {
        let raw_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let res = Response::Data { data: raw_data.clone() };
        let bin = res.to_binary();
        let decoded = Response::from_binary(&bin).unwrap();

        if let Response::Data { data } = decoded {
            assert_eq!(data, raw_data);
        } else {
            panic!("Expected Data variant");
        }
    }
}
