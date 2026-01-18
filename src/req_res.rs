use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

#[derive(Debug, PartialEq, Clone)]
pub struct ReqRes {
    pub fields: HashMap<String, Vec<u8>>,
}

impl ReqRes {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Serializes the object into: [len_key][key][len_value][value]...
    /// Note: len_object is omitted here as it is handled by the socket layer.
    pub fn to_binary(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        for (key, value) in &self.fields {
            let key_bytes = key.as_bytes();

            // Write key length (u32 BE) and key string
            buffer.write_all(&(key_bytes.len() as u32).to_be_bytes()).unwrap();
            buffer.write_all(key_bytes).unwrap();

            // Write value length (u32 BE) and value bytes
            buffer.write_all(&(value.len() as u32).to_be_bytes()).unwrap();
            buffer.write_all(value).unwrap();
        }

        buffer
    }

    /// Deserializes the binary data.
    /// Assumes the socket layer has already stripped the 'len_object' prefix.
    pub fn from_binary(bytes: &[u8]) -> Result<Self, String> {
        let mut fields = HashMap::new();
        let mut cursor = Cursor::new(bytes);

        while (cursor.position() as usize) < bytes.len() {
            // 1. Read Key Length
            let mut len_buf = [0u8; 4];
            if cursor.read_exact(&mut len_buf).is_err() { break; }
            let key_len = u32::from_be_bytes(len_buf) as usize;

            // 2. Read Key
            let mut key_buf = vec![0u8; key_len];
            cursor.read_exact(&mut key_buf).map_err(|_| "Failed to read key")?;
            let key = String::from_utf8(key_buf).map_err(|_| "Invalid UTF-8 key")?;

            // 3. Read Value Length
            if cursor.read_exact(&mut len_buf).is_err() { return Err("Missing value length".into()); }
            let val_len = u32::from_be_bytes(len_buf) as usize;

            // 4. Read Value
            let mut val_buf = vec![0u8; val_len];
            cursor.read_exact(&mut val_buf).map_err(|_| "Failed to read value")?;

            fields.insert(key, val_buf);
        }

        Ok(Self { fields })
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialization_roundtrip() {
        let mut original = ReqRes::new();
        original.fields.insert("command".to_string(), "ping".as_bytes().to_vec());
        original.fields.insert("id".to_string(), vec![0x01, 0x02, 0x03]);

        let binary = original.to_binary();
        let decoded = ReqRes::from_binary(&binary).expect("Failed to decode");

        assert_eq!(original, decoded);
        assert_eq!(decoded.fields.get("command").unwrap(), "ping".as_bytes());
    }

    #[test]
    fn test_empty_payload() {
        let empty = ReqRes::new();
        let binary = empty.to_binary();
        let decoded = ReqRes::from_binary(&binary).unwrap();

        assert!(decoded.fields.is_empty());
    }

    #[test]
    fn test_malformed_data() {
        // Provide 4 bytes indicating a long key, but no actual key data
        let malformed = vec![0, 0, 0, 10];
        let result = ReqRes::from_binary(&malformed);

        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_fields() {
        let mut msg = ReqRes::new();
        msg.fields.insert("a".into(), vec![1]);
        msg.fields.insert("b".into(), vec![2]);
        msg.fields.insert("c".into(), vec![3]);

        let binary = msg.to_binary();
        let decoded = ReqRes::from_binary(&binary).unwrap();

        assert_eq!(decoded.fields.len(), 3);
        assert_eq!(decoded.fields.get("b").unwrap(), &vec![2]);
    }
}
