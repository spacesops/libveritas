use std::fmt;
use std::io::{Read, Write};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A version-prefixed data container for space records.
///
/// The first byte is a version number that determines the format:
/// - Version 0: UTF-8 JSON array of `[key, value]` pairs, sorted by key.
///   Example: `[["ipv4","127.0.0.1"],["nostr","npub1..."]]`
/// - Other versions: opaque binary data
///
/// Use [`records()`](RawRecords::records) to parse version 0 data, and
/// [`from_records()`](RawRecords::from_records) to create version 0 data.
#[derive(Clone, Debug, PartialEq)]
pub struct RawRecords {
    bytes: Vec<u8>,
}

/// A single key-value record (version 0 format).
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub name: String,
    pub value: String,
}

/// Errors when working with records.
#[derive(Debug, Clone)]
pub enum RecordsError {
    /// Data is empty (no version byte)
    Empty,
    /// Version is not supported for record parsing
    UnsupportedVersion(u8),
    /// Data is not valid UTF-8 (version 0)
    InvalidUtf8,
    /// Data is not valid JSON (version 0)
    InvalidJson(String),
}

impl fmt::Display for RecordsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty data (no version byte)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version: {}", v),
            Self::InvalidUtf8 => write!(f, "data is not valid UTF-8"),
            Self::InvalidJson(e) => write!(f, "invalid JSON: {}", e),
        }
    }
}

impl std::error::Error for RecordsError {}

impl RawRecords {
    /// Create a new RawRecords with the given version and data.
    pub fn new(version: u8, data: Vec<u8>) -> Self {
        let mut bytes = Vec::with_capacity(1 + data.len());
        bytes.push(version);
        bytes.extend(data);
        Self { bytes }
    }

    /// Parse from raw bytes where the first byte is the version.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecordsError> {
        if bytes.is_empty() {
            return Err(RecordsError::Empty);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Serialize to bytes (version byte + data).
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// View the full byte representation (version byte + data).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The version byte.
    pub fn version(&self) -> u8 {
        self.bytes[0]
    }

    /// The data after the version byte.
    pub fn data(&self) -> &[u8] {
        &self.bytes[1..]
    }

    /// Parse version 0 records from the data.
    ///
    /// Version 0 format is a JSON array of `[key, value]` pairs sorted by key.
    /// Returns an error if the version is not 0 or the data is not valid JSON.
    pub fn records(&self) -> Result<Vec<Record>, RecordsError> {
        if self.version() != 0 {
            return Err(RecordsError::UnsupportedVersion(self.version()));
        }
        let text =
            std::str::from_utf8(self.data()).map_err(|_| RecordsError::InvalidUtf8)?;
        if text.is_empty() {
            return Ok(Vec::new());
        }
        let pairs: Vec<(String, String)> =
            serde_json::from_str(text)
                .map_err(|e| RecordsError::InvalidJson(e.to_string()))?;
        Ok(pairs
            .into_iter()
            .map(|(name, value)| Record { name, value })
            .collect())
    }

    /// Create a version 0 RawRecords from a list of records.
    ///
    /// Records are sorted by key for deterministic serialization.
    /// Format: `[["key1","val1"],["key2","val2"]]`
    pub fn from_records(records: &[Record]) -> Self {
        let mut pairs: Vec<(&str, &str)> = records
            .iter()
            .map(|r| (r.name.as_str(), r.value.as_str()))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(b.0));
        let json = serde_json::to_string(&pairs).expect("serialize records");
        Self::new(0, json.into_bytes())
    }
}

impl Serialize for RawRecords {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry("version", &self.version())?;
            if self.version() == 0 {
                let text = std::str::from_utf8(self.data())
                    .map_err(serde::ser::Error::custom)?;
                if text.is_empty() {
                    let empty: Vec<(String, String)> = vec![];
                    map.serialize_entry("data", &empty)?;
                } else {
                    let value: serde_json::Value =
                        serde_json::from_str(text).map_err(serde::ser::Error::custom)?;
                    map.serialize_entry("data", &value)?;
                }
            } else {
                map.serialize_entry("data", &BASE64.encode(self.data()))?;
            }
            map.end()
        } else {
            serde::Serialize::serialize(&self.bytes, serializer)
        }
    }
}

impl<'de> Deserialize<'de> for RawRecords {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            #[derive(Deserialize)]
            struct Helper {
                version: u8,
                data: serde_json::Value,
            }
            let helper = Helper::deserialize(deserializer)?;
            if helper.version == 0 {
                // Re-serialize the array data to canonical form
                let pairs: Vec<(String, String)> = serde_json::from_value(helper.data)
                    .map_err(serde::de::Error::custom)?;
                let json = serde_json::to_string(&pairs)
                    .map_err(serde::de::Error::custom)?;
                Ok(RawRecords::new(0, json.into_bytes()))
            } else {
                let s = helper.data.as_str().ok_or_else(|| {
                    serde::de::Error::custom("expected base64 string for non-v0 data")
                })?;
                let bytes = BASE64.decode(s).map_err(serde::de::Error::custom)?;
                Ok(RawRecords::new(helper.version, bytes))
            }
        } else {
            let bytes = <Vec<u8> as Deserialize>::deserialize(deserializer)?;
            RawRecords::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

impl BorshSerialize for RawRecords {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.bytes, writer)
    }
}

impl BorshDeserialize for RawRecords {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes = Vec::<u8>::deserialize_reader(reader)?;
        RawRecords::from_bytes(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_v0() {
        let records = vec![
            Record {
                name: "nostr".to_string(),
                value: "npub1abc".to_string(),
            },
            Record {
                name: "address".to_string(),
                value: "bc1q...".to_string(),
            },
        ];

        let raw = RawRecords::from_records(&records);
        assert_eq!(raw.version(), 0);

        // Verify sorted array-of-pairs format
        let text = std::str::from_utf8(raw.data()).unwrap();
        assert_eq!(text, r#"[["address","bc1q..."],["nostr","npub1abc"]]"#);

        let bytes = raw.to_vec();
        let parsed = RawRecords::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version(), 0);

        let parsed_records = parsed.records().unwrap();
        assert_eq!(parsed_records.len(), 2);
        // Records come back in sorted order
        assert_eq!(parsed_records[0].name, "address");
        assert_eq!(parsed_records[0].value, "bc1q...");
        assert_eq!(parsed_records[1].name, "nostr");
        assert_eq!(parsed_records[1].value, "npub1abc");
    }

    #[test]
    fn test_deterministic_serialization() {
        // Different input orders produce identical bytes
        let a = RawRecords::from_records(&[
            Record { name: "z".to_string(), value: "last".to_string() },
            Record { name: "a".to_string(), value: "first".to_string() },
        ]);
        let b = RawRecords::from_records(&[
            Record { name: "a".to_string(), value: "first".to_string() },
            Record { name: "z".to_string(), value: "last".to_string() },
        ]);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn test_roundtrip_other_version() {
        let raw = RawRecords::new(42, vec![1, 2, 3, 4]);
        assert_eq!(raw.version(), 42);
        assert_eq!(raw.data(), &[1, 2, 3, 4]);

        let bytes = raw.to_vec();
        assert_eq!(bytes[0], 42);
        assert_eq!(&bytes[1..], &[1, 2, 3, 4]);

        let parsed = RawRecords::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version(), 42);
        assert_eq!(parsed.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_empty_bytes_error() {
        assert!(matches!(
            RawRecords::from_bytes(&[]),
            Err(RecordsError::Empty)
        ));
    }

    #[test]
    fn test_records_wrong_version() {
        let raw = RawRecords::new(1, vec![]);
        assert!(matches!(
            raw.records(),
            Err(RecordsError::UnsupportedVersion(1))
        ));
    }

    #[test]
    fn test_v0_empty_data() {
        let raw = RawRecords::new(0, vec![]);
        let records = raw.records().unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_serde_json_v0() {
        let raw = RawRecords::from_records(&[Record {
            name: "nostr".to_string(),
            value: "npub1abc".to_string(),
        }]);

        let json = serde_json::to_string(&raw).unwrap();
        assert!(json.contains("\"version\":0"));
        // v0 data is an array of pairs
        assert!(json.contains(r#"[["nostr","npub1abc"]]"#));

        let parsed: RawRecords = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version(), 0);
        let records = parsed.records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "nostr");
        assert_eq!(records[0].value, "npub1abc");
    }

    #[test]
    fn test_serde_json_other_version() {
        let raw = RawRecords::new(5, vec![0xDE, 0xAD]);
        let json = serde_json::to_string(&raw).unwrap();
        assert!(json.contains("\"version\":5"));
        // data should be base64
        assert!(json.contains("\"data\":\"3q0=\""));

        let parsed: RawRecords = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version(), 5);
        assert_eq!(parsed.data(), &[0xDE, 0xAD]);
    }

    #[test]
    fn test_borsh_roundtrip() {
        let raw = RawRecords::from_records(&[Record {
            name: "test".to_string(),
            value: "value".to_string(),
        }]);

        let borsh_bytes = borsh::to_vec(&raw).unwrap();
        let parsed: RawRecords = borsh::from_slice(&borsh_bytes).unwrap();
        assert_eq!(parsed.version(), raw.version());
        assert_eq!(parsed.data(), raw.data());
    }
}
