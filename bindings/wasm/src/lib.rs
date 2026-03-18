use std::str::FromStr;
use wasm_bindgen::prelude::*;

use libveritas::builder;
use libveritas::msg;
use libveritas::sname::SName;
use serde::Serialize;
use spaces_nums::RootAnchor;
use spaces_protocol::bitcoin::ScriptBuf;
use spaces_protocol::slabel::SLabel;

/// Serialize through JSON to get human-readable serde output
/// (hex hashes, string names, etc.) as a native JS object.
fn to_js<T: Serialize>(val: &T) -> Result<JsValue, JsError> {
    let json = serde_json::to_string(val).map_err(|e| JsError::new(&e.to_string()))?;
    js_sys::JSON::parse(&json).map_err(|_| JsError::new("json parse failed"))
}

/// Extract an optional Uint8Array field from a JS object.
fn get_optional_bytes(obj: &JsValue, key: &str) -> Option<Vec<u8>> {
    let val = js_sys::Reflect::get(obj, &key.into()).ok()?;
    if val.is_undefined() || val.is_null() {
        return None;
    }
    Some(js_sys::Uint8Array::from(val).to_vec())
}

/// Parse a JS object into a DataUpdateRequest (name + records, no cert).
fn parse_data_update(entry: &JsValue) -> Result<builder::DataUpdateRequest, JsError> {
    let name = js_sys::Reflect::get(entry, &"name".into())
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| JsError::new("name is required and must be a string"))?;

    let handle = SName::from_str(&name)
        .map_err(|e| JsError::new(&format!("invalid name '{}': {}", name, e)))?;

    let records = get_optional_bytes(entry, "records")
        .map(|b| msg::OffchainRecords::from_slice(&b))
        .transpose()
        .map_err(|e| JsError::new(&format!("invalid records: {e}")))?;

    let delegate_records = get_optional_bytes(entry, "delegateRecords")
        .map(|b| msg::OffchainRecords::from_slice(&b))
        .transpose()
        .map_err(|e| JsError::new(&format!("invalid delegate_records: {e}")))?;

    Ok(builder::DataUpdateRequest {
        handle,
        records,
        delegate_records,
    })
}

/// Parse a JS object into an UpdateRequest (name + offchain data + optional cert).
fn parse_update_entry(entry: &JsValue) -> Result<builder::UpdateRequest, JsError> {
    let data = parse_data_update(entry)?;
    let cert = get_optional_bytes(entry, "cert")
        .map(|b| libveritas::cert::Certificate::from_slice(&b))
        .transpose()
        .map_err(|e| JsError::new(&format!("invalid cert: {e}")))?;

    Ok(builder::UpdateRequest { data, cert })
}

/// Parse a JS array of UpdateRequests (for MessageBuilder).
fn parse_update_entries(updates: &JsValue) -> Result<Vec<builder::UpdateRequest>, JsError> {
    let array = js_sys::Array::from(updates);
    let mut reqs = Vec::with_capacity(array.length() as usize);
    for i in 0..array.length() {
        reqs.push(parse_update_entry(&array.get(i))?);
    }
    Ok(reqs)
}

/// Parse a JS array of DataUpdateRequests (for Message.update).
fn parse_data_updates(updates: &JsValue) -> Result<Vec<builder::DataUpdateRequest>, JsError> {
    let array = js_sys::Array::from(updates);
    let mut reqs = Vec::with_capacity(array.length() as usize);
    for i in 0..array.length() {
        reqs.push(parse_data_update(&array.get(i))?);
    }
    Ok(reqs)
}

#[wasm_bindgen]
pub struct QueryContext {
    inner: msg::QueryContext,
}

#[wasm_bindgen]
impl QueryContext {
    #[wasm_bindgen(constructor)]
    pub fn new() -> QueryContext {
        QueryContext {
            inner: msg::QueryContext::new(),
        }
    }

    /// Add a handle to verify (e.g. "alice@bitcoin").
    /// If no requests are added, all handles in the message are verified.
    pub fn add_request(&mut self, handle: &str) -> Result<(), JsError> {
        let sname = SName::from_str(handle)
            .map_err(|e| JsError::new(&format!("invalid handle: {e}")))?;
        self.inner.add_request(sname);
        Ok(())
    }

    /// Add a known zone from stored bytes (from a previous verification).
    pub fn add_zone(&mut self, zone_bytes: &[u8]) -> Result<(), JsError> {
        let zone = libveritas::Zone::from_slice(zone_bytes)
            .map_err(|e| JsError::new(&format!("invalid zone: {e}")))?;
        self.inner.add_zone(zone);
        Ok(())
    }
}

// -- Zone conversions (plain JS object ↔ inner Zone) --

fn delegate_to_js(d: &libveritas::ProvableOption<libveritas::Delegate>) -> JsValue {
    let obj = js_sys::Object::new();
    match d {
        libveritas::ProvableOption::Exists { value } => {
            js_sys::Reflect::set(&obj, &"type".into(), &"exists".into()).unwrap();
            js_sys::Reflect::set(&obj, &"scriptPubkey".into(),
                &js_sys::Uint8Array::from(value.script_pubkey.as_bytes()).into()).unwrap();
            js_sys::Reflect::set(&obj, &"records".into(), &match &value.records {
                Some(d) => js_sys::Uint8Array::from(d.as_slice()).into(),
                None => JsValue::NULL,
            }).unwrap();
            js_sys::Reflect::set(&obj, &"fallbackRecords".into(), &match &value.fallback_records {
                Some(d) => js_sys::Uint8Array::from(d.as_slice()).into(),
                None => JsValue::NULL,
            }).unwrap();
        }
        libveritas::ProvableOption::Empty => {
            js_sys::Reflect::set(&obj, &"type".into(), &"empty".into()).unwrap();
        }
        libveritas::ProvableOption::Unknown => {
            js_sys::Reflect::set(&obj, &"type".into(), &"unknown".into()).unwrap();
        }
    }
    obj.into()
}

fn commitment_to_js(c: &libveritas::ProvableOption<libveritas::CommitmentInfo>) -> JsValue {
    let obj = js_sys::Object::new();
    match c {
        libveritas::ProvableOption::Exists { value } => {
            js_sys::Reflect::set(&obj, &"type".into(), &"exists".into()).unwrap();
            js_sys::Reflect::set(&obj, &"stateRoot".into(),
                &js_sys::Uint8Array::from(&value.onchain.state_root[..]).into()).unwrap();
            js_sys::Reflect::set(&obj, &"prevRoot".into(), &match &value.onchain.prev_root {
                Some(r) => js_sys::Uint8Array::from(&r[..]).into(),
                None => JsValue::NULL,
            }).unwrap();
            js_sys::Reflect::set(&obj, &"rollingHash".into(),
                &js_sys::Uint8Array::from(&value.onchain.rolling_hash[..]).into()).unwrap();
            js_sys::Reflect::set(&obj, &"blockHeight".into(),
                &value.onchain.block_height.into()).unwrap();
            js_sys::Reflect::set(&obj, &"receiptHash".into(), &match &value.receipt_hash {
                Some(h) => js_sys::Uint8Array::from(&h[..]).into(),
                None => JsValue::NULL,
            }).unwrap();
        }
        libveritas::ProvableOption::Empty => {
            js_sys::Reflect::set(&obj, &"type".into(), &"empty".into()).unwrap();
        }
        libveritas::ProvableOption::Unknown => {
            js_sys::Reflect::set(&obj, &"type".into(), &"unknown".into()).unwrap();
        }
    }
    obj.into()
}

fn zone_to_js(z: &libveritas::Zone) -> JsValue {
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"anchor".into(), &z.anchor.into()).unwrap();
    js_sys::Reflect::set(&obj, &"sovereignty".into(), &z.sovereignty.to_string().into()).unwrap();
    js_sys::Reflect::set(&obj, &"handle".into(), &z.handle.to_string().into()).unwrap();
    js_sys::Reflect::set(&obj, &"alias".into(), &match &z.alias {
        Some(a) => a.to_string().into(),
        None => JsValue::NULL,
    }).unwrap();
    js_sys::Reflect::set(&obj, &"scriptPubkey".into(),
        &js_sys::Uint8Array::from(z.script_pubkey.as_bytes()).into()).unwrap();
    js_sys::Reflect::set(&obj, &"records".into(), &match &z.records {
        Some(d) => js_sys::Uint8Array::from(d.as_slice()).into(),
        None => JsValue::NULL,
    }).unwrap();
    js_sys::Reflect::set(&obj, &"fallbackRecords".into(), &match &z.fallback_records {
        Some(d) => js_sys::Uint8Array::from(d.as_slice()).into(),
        None => JsValue::NULL,
    }).unwrap();
    js_sys::Reflect::set(&obj, &"delegate".into(), &delegate_to_js(&z.delegate)).unwrap();
    js_sys::Reflect::set(&obj, &"commitment".into(), &commitment_to_js(&z.commitment)).unwrap();
    obj.into()
}

fn get_js_string(obj: &JsValue, key: &str) -> Option<String> {
    js_sys::Reflect::get(obj, &key.into()).ok().and_then(|v| v.as_string())
}

fn get_js_u32(obj: &JsValue, key: &str) -> Option<u32> {
    js_sys::Reflect::get(obj, &key.into()).ok().and_then(|v| v.as_f64()).map(|n| n as u32)
}

fn delegate_from_js(val: &JsValue) -> Result<libveritas::ProvableOption<libveritas::Delegate>, JsError> {
    let dtype = get_js_string(val, "type")
        .ok_or_else(|| JsError::new("delegate.type is required"))?;
    match dtype.as_str() {
        "exists" => {
            let spk = get_optional_bytes(val, "scriptPubkey")
                .ok_or_else(|| JsError::new("delegate.scriptPubkey is required"))?;
            Ok(libveritas::ProvableOption::Exists {
                value: libveritas::Delegate {
                    script_pubkey: ScriptBuf::from_bytes(spk),
                    records: get_optional_bytes(val, "records").map(|d| sip7::RecordSet::new(d)),
                    fallback_records: get_optional_bytes(val, "fallbackRecords").map(|d| sip7::RecordSet::new(d)),
                },
            })
        }
        "empty" => Ok(libveritas::ProvableOption::Empty),
        "unknown" => Ok(libveritas::ProvableOption::Unknown),
        _ => Err(JsError::new(&format!("unknown delegate type: {dtype}"))),
    }
}

fn bytes32_from_js(val: &JsValue, key: &str) -> Result<[u8; 32], JsError> {
    let bytes = get_optional_bytes(val, key)
        .ok_or_else(|| JsError::new(&format!("{key} is required")))?;
    let arr: [u8; 32] = bytes.try_into()
        .map_err(|_| JsError::new(&format!("{key} must be 32 bytes")))?;
    Ok(arr)
}

fn optional_bytes32_from_js(val: &JsValue, key: &str) -> Result<Option<[u8; 32]>, JsError> {
    match get_optional_bytes(val, key) {
        Some(bytes) => {
            let arr: [u8; 32] = bytes.try_into()
                .map_err(|_| JsError::new(&format!("{key} must be 32 bytes")))?;
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

fn commitment_from_js(val: &JsValue) -> Result<libveritas::ProvableOption<libveritas::CommitmentInfo>, JsError> {
    let ctype = get_js_string(val, "type")
        .ok_or_else(|| JsError::new("commitment.type is required"))?;
    match ctype.as_str() {
        "exists" => {
            Ok(libveritas::ProvableOption::Exists {
                value: libveritas::CommitmentInfo {
                    onchain: spaces_nums::Commitment {
                        state_root: bytes32_from_js(val, "stateRoot")?,
                        prev_root: optional_bytes32_from_js(val, "prevRoot")?,
                        rolling_hash: bytes32_from_js(val, "rollingHash")?,
                        block_height: get_js_u32(val, "blockHeight")
                            .ok_or_else(|| JsError::new("commitment.blockHeight is required"))?,
                    },
                    receipt_hash: optional_bytes32_from_js(val, "receiptHash")?,
                },
            })
        }
        "empty" => Ok(libveritas::ProvableOption::Empty),
        "unknown" => Ok(libveritas::ProvableOption::Unknown),
        _ => Err(JsError::new(&format!("unknown commitment type: {ctype}"))),
    }
}

fn zone_from_js(val: &JsValue) -> Result<libveritas::Zone, JsError> {
    let handle_str = get_js_string(val, "handle")
        .ok_or_else(|| JsError::new("handle is required"))?;
    let handle = SName::from_str(&handle_str)
        .map_err(|e| JsError::new(&format!("invalid handle: {e}")))?;
    let alias = get_js_string(val, "alias")
        .map(|a| SLabel::from_str_unprefixed(&a))
        .transpose()
        .map_err(|e| JsError::new(&format!("invalid alias: {e}")))?;
    let spk = get_optional_bytes(val, "scriptPubkey")
        .ok_or_else(|| JsError::new("scriptPubkey is required"))?;
    let sovereignty_str = get_js_string(val, "sovereignty").unwrap_or_default();
    let delegate_val = js_sys::Reflect::get(val, &"delegate".into())
        .map_err(|_| JsError::new("delegate is required"))?;
    let commitment_val = js_sys::Reflect::get(val, &"commitment".into())
        .map_err(|_| JsError::new("commitment is required"))?;

    Ok(libveritas::Zone {
        anchor: get_js_u32(val, "anchor").unwrap_or(0),
        sovereignty: match sovereignty_str.as_str() {
            "sovereign" => libveritas::SovereigntyState::Sovereign,
            "pending" => libveritas::SovereigntyState::Pending,
            _ => libveritas::SovereigntyState::Dependent,
        },
        handle,
        alias,
        script_pubkey: ScriptBuf::from_bytes(spk),
        records: get_optional_bytes(val, "records").map(|d| sip7::RecordSet::new(d)),
        fallback_records: get_optional_bytes(val, "fallbackRecords").map(|d| sip7::RecordSet::new(d)),
        delegate: delegate_from_js(&delegate_val)?,
        commitment: commitment_from_js(&commitment_val)?,
    })
}

/// A message containing chain proofs and handle data.
#[wasm_bindgen]
pub struct Message {
    inner: msg::Message,
}

#[wasm_bindgen]
impl Message {
    /// Decode a message from borsh bytes.
    #[wasm_bindgen(constructor)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, JsError> {
        let inner = msg::Message::from_slice(bytes)
            .map_err(|e| JsError::new(&format!("invalid message: {e}")))?;
        Ok(Message { inner })
    }

    /// Serialize the message to borsh bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// Update records on this message.
    ///
    /// Accepts a JS array of data update entries:
    /// ```js
    /// msg.update([
    ///   { name: "alice@bitcoin", records: Uint8Array },
    ///   { name: "@bitcoin", delegateRecords: Uint8Array }
    /// ])
    /// ```
    ///
    /// To update certificates, construct a new message instead.
    pub fn update(&mut self, updates: JsValue) -> Result<(), JsError> {
        let reqs = parse_data_updates(&updates)?;
        self.inner.update(reqs);
        Ok(())
    }
}

/// Builder for constructing messages from update requests and chain proofs.
#[wasm_bindgen]
pub struct MessageBuilder {
    inner: Option<builder::MessageBuilder>,
}

#[wasm_bindgen]
impl MessageBuilder {
    /// Create a builder from a JS array of update requests.
    ///
    /// ```js
    /// let builder = new MessageBuilder([
    ///   { name: "@bitcoin", records: Uint8Array, cert: Uint8Array },
    ///   { name: "alice@bitcoin", records: Uint8Array, cert: Uint8Array }
    /// ])
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(requests: JsValue) -> Result<MessageBuilder, JsError> {
        let reqs = parse_update_entries(&requests)?;
        Ok(MessageBuilder {
            inner: Some(builder::MessageBuilder::new(reqs)),
        })
    }

    /// Returns the chain proof request as a JS object.
    ///
    /// Send this to the provider/fabric to get the chain proofs needed for `build()`.
    pub fn chain_proof_request(&self) -> Result<JsValue, JsError> {
        let builder = self
            .inner
            .as_ref()
            .ok_or_else(|| JsError::new("builder already consumed by build()"))?;
        to_js(&builder.chain_proof_request())
    }

    /// Build the message from a borsh-encoded ChainProof.
    ///
    /// Consumes the builder — cannot be called twice.
    pub fn build(&mut self, chain_proof: &[u8]) -> Result<Message, JsError> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("builder already consumed by build()"))?;
        let chain = msg::ChainProof::from_slice(chain_proof)
            .map_err(|e| JsError::new(&format!("invalid chain proof: {e}")))?;
        let msg = builder
            .build(chain)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Message { inner: msg })
    }
}

#[wasm_bindgen]
pub struct Veritas {
    inner: libveritas::Veritas,
}

#[wasm_bindgen]
impl Veritas {
    #[wasm_bindgen(constructor)]
    pub fn new(anchors: JsValue) -> Result<Veritas, JsError> {
        let anchors: Vec<RootAnchor> = serde_wasm_bindgen::from_value(anchors)
            .map_err(|e| JsError::new(&format!("invalid anchors: {e}")))?;
        let inner = libveritas::Veritas::new()
            .with_anchors(anchors)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Veritas { inner })
    }

    #[wasm_bindgen(js_name = "withDevMode")]
    pub fn with_dev_mode(anchors: JsValue) -> Result<Veritas, JsError> {
        let anchors: Vec<RootAnchor> = serde_wasm_bindgen::from_value(anchors)
            .map_err(|e| JsError::new(&format!("invalid anchors: {e}")))?;
        let inner = libveritas::Veritas::new()
            .with_anchors(anchors)
            .map_err(|e| JsError::new(&e.to_string()))?
            .with_dev_mode(true);
        Ok(Veritas { inner })
    }

    pub fn oldest_anchor(&self) -> u32 {
        self.inner.oldest_anchor()
    }

    pub fn newest_anchor(&self) -> u32 {
        self.inner.newest_anchor()
    }

    #[wasm_bindgen(js_name = "computeAnchorSetHash")]
    pub fn compute_anchor_set_hash(&self) -> Vec<u8> {
        self.inner.compute_anchor_set_hash().to_vec()
    }

    pub fn is_finalized(&self, commitment_height: u32) -> bool {
        self.inner.is_finalized(commitment_height)
    }

    pub fn sovereignty_for(&self, commitment_height: u32) -> String {
        self.inner.sovereignty_for(commitment_height).to_string()
    }

    /// Verify a message against a query context.
    pub fn verify_message(
        &self,
        ctx: &QueryContext,
        msg: &Message,
    ) -> Result<VerifiedMessage, JsError> {
        let inner = self
            .inner
            .verify_message(&ctx.inner, msg.inner.clone())
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(VerifiedMessage { inner })
    }
}

/// Result of verifying a message.
#[wasm_bindgen]
pub struct VerifiedMessage {
    inner: libveritas::VerifiedMessage,
}

#[wasm_bindgen]
impl VerifiedMessage {
    /// All verified zones as plain JS objects.
    pub fn zones(&self) -> JsValue {
        let array = js_sys::Array::new();
        for z in &self.inner.zones {
            array.push(&zone_to_js(z));
        }
        array.into()
    }

    /// Get certificate for a specific handle (e.g. "alice@bitcoin").
    /// Returns null if the handle was not verified.
    pub fn certificate(&self, handle: &str) -> Result<JsValue, JsError> {
        let sname = SName::from_str(handle)
            .map_err(|e| JsError::new(&format!("invalid handle: {e}")))?;
        match self.inner.certificate(&sname) {
            Some(cert) => to_js(&cert),
            None => Ok(JsValue::NULL),
        }
    }

    /// All certificates as a JS array.
    pub fn certificates(&self) -> Result<JsValue, JsError> {
        let certs: Vec<_> = self.inner.certificates().collect();
        to_js(&certs)
    }

    /// Get the verified message for rebroadcasting or updating.
    pub fn message(&self) -> Message {
        Message {
            inner: self.inner.message.clone(),
        }
    }

    /// Get the verified message as borsh bytes.
    pub fn message_bytes(&self) -> Vec<u8> {
        self.inner.message.to_bytes()
    }
}

// ── Record / RecordSet ────────────────────────────────────────────

fn parse_js_record(obj: &JsValue) -> Result<sip7::Record, JsError> {
    let rtype = js_sys::Reflect::get(obj, &"type".into())
        .ok().and_then(|v| v.as_string())
        .ok_or_else(|| JsError::new("record must have a 'type' field"))?;
    match rtype.as_str() {
        "seq" => {
            let version = js_sys::Reflect::get(obj, &"version".into())
                .ok().and_then(|v| v.as_f64())
                .ok_or_else(|| JsError::new("seq record: 'version' must be a number"))? as u64;
            Ok(sip7::Record::seq(version))
        }
        "txt" => {
            let key = js_sys::Reflect::get(obj, &"key".into())
                .ok().and_then(|v| v.as_string())
                .ok_or_else(|| JsError::new("txt record: 'key' must be a string"))?;
            let value = js_sys::Reflect::get(obj, &"value".into())
                .ok().and_then(|v| v.as_string())
                .ok_or_else(|| JsError::new("txt record: 'value' must be a string"))?;
            Ok(sip7::Record::txt(&key, &value))
        }
        "blob" => {
            let key = js_sys::Reflect::get(obj, &"key".into())
                .ok().and_then(|v| v.as_string())
                .ok_or_else(|| JsError::new("blob record: 'key' must be a string"))?;
            let value = js_sys::Reflect::get(obj, &"value".into())
                .map(|v| js_sys::Uint8Array::from(v).to_vec())
                .map_err(|_| JsError::new("blob record: 'value' must be a Uint8Array"))?;
            Ok(sip7::Record::blob(&key, value))
        }
        "unknown" => {
            let rt = js_sys::Reflect::get(obj, &"rtype".into())
                .ok().and_then(|v| v.as_f64())
                .ok_or_else(|| JsError::new("unknown record: 'rtype' must be a number"))? as u8;
            let rdata = js_sys::Reflect::get(obj, &"rdata".into())
                .map(|v| js_sys::Uint8Array::from(v).to_vec())
                .map_err(|_| JsError::new("unknown record: 'rdata' must be a Uint8Array"))?;
            Ok(sip7::Record::unknown(rt, rdata))
        }
        other => Err(JsError::new(&format!("unknown record type: {other}"))),
    }
}

fn sip7_record_to_js(record: &sip7::Record) -> JsValue {
    match record {
        sip7::Record::Seq(version) => Record::seq(*version),
        sip7::Record::Txt { key, value } => Record::txt(key, value),
        sip7::Record::Blob { key, value } => Record::blob(key, value),
        sip7::Record::Unknown { rtype, rdata } => Record::unknown(*rtype, rdata),
    }
}

/// Record constructors for building a RecordSet.
///
/// ```js
/// const rs = RecordSet.pack([
///     Record.txt("btc", "bc1qtest"),
///     Record.blob("avatar", pngBytes),
///     Record.unknown(0x10, raw),
/// ]);
/// ```
#[wasm_bindgen]
pub struct Record;

#[wasm_bindgen]
impl Record {
    pub fn seq(version: u64) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"seq".into()).unwrap();
        js_sys::Reflect::set(&obj, &"version".into(), &version.into()).unwrap();
        obj.into()
    }

    pub fn txt(key: &str, value: &str) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"txt".into()).unwrap();
        js_sys::Reflect::set(&obj, &"key".into(), &key.into()).unwrap();
        js_sys::Reflect::set(&obj, &"value".into(), &value.into()).unwrap();
        obj.into()
    }

    pub fn blob(key: &str, value: &[u8]) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"blob".into()).unwrap();
        js_sys::Reflect::set(&obj, &"key".into(), &key.into()).unwrap();
        js_sys::Reflect::set(&obj, &"value".into(), &js_sys::Uint8Array::from(value)).unwrap();
        obj.into()
    }

    pub fn unknown(rtype: u8, rdata: &[u8]) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"unknown".into()).unwrap();
        js_sys::Reflect::set(&obj, &"rtype".into(), &rtype.into()).unwrap();
        js_sys::Reflect::set(&obj, &"rdata".into(), &js_sys::Uint8Array::from(rdata)).unwrap();
        obj.into()
    }
}

/// SIP-7 record set — wire-format encoded records.
///
/// ```js
/// // Pack from records
/// const rs = RecordSet.pack([Record.txt("btc", "bc1qtest")]);
/// const wire = rs.toBytes();
///
/// // Load from wire bytes
/// const rs = new RecordSet(wire);
/// for (const r of rs.unpack()) { ... }
/// ```
#[wasm_bindgen]
pub struct RecordSet {
    inner: sip7::RecordSet,
}

#[wasm_bindgen]
impl RecordSet {
    /// Wrap raw wire bytes (lazy — no parsing until unpack).
    #[wasm_bindgen(constructor)]
    pub fn new(data: &[u8]) -> RecordSet {
        RecordSet { inner: sip7::RecordSet::new(data.to_vec()) }
    }

    /// Pack records into wire format.
    pub fn pack(records: JsValue) -> Result<RecordSet, JsError> {
        let array = js_sys::Array::from(&records);
        let mut sip_records = Vec::with_capacity(array.length() as usize);
        for i in 0..array.length() {
            sip_records.push(parse_js_record(&array.get(i))?);
        }
        let inner = sip7::RecordSet::pack(sip_records)
            .map_err(|e| JsError::new(&format!("pack failed: {e}")))?;
        Ok(RecordSet { inner })
    }

    /// Raw wire bytes.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_slice().to_vec()
    }

    /// Parse all records.
    pub fn unpack(&self) -> Result<JsValue, JsError> {
        let records = self.inner.unpack()
            .map_err(|e| JsError::new(&format!("unpack failed: {e}")))?;
        let array = js_sys::Array::new();
        for record in records {
            array.push(&sip7_record_to_js(&record));
        }
        Ok(array.into())
    }

    #[wasm_bindgen(js_name = "isEmpty")]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// The 32-byte signing hash (Spaces signed-message prefix + SHA256).
    #[wasm_bindgen(js_name = "signingId")]
    pub fn signing_id(&self) -> Vec<u8> {
        let msg = libveritas::hash_signable_message(self.inner.as_slice());
        msg.as_ref().to_vec()
    }
}

/// Helpers for constructing OffchainRecords (signed record sets).
///
/// ```js
/// const rs = RecordSet.pack([Record.seq(0), Record.txt("btc", "bc1qtest")]);
/// const sig = await wallet.signSchnorr(rs.signingId());
/// const bytes = OffchainRecords.from(rs, sig);
/// ```
#[wasm_bindgen]
pub struct OffchainRecords;

#[wasm_bindgen]
impl OffchainRecords {
    /// Create borsh-encoded OffchainRecords from a RecordSet and 64-byte signature.
    pub fn from(record_set: &RecordSet, signature: &[u8]) -> Result<Vec<u8>, JsError> {
        let sig: [u8; 64] = signature.try_into()
            .map_err(|_| JsError::new("signature must be 64 bytes"))?;
        let offchain = msg::OffchainRecords::new(
            record_set.inner.clone(),
            libveritas::cert::Signature(sig),
        );
        Ok(offchain.to_bytes())
    }
}

/// Hash a message with the Spaces signed-message prefix (SHA256).
/// Returns the 32-byte digest suitable for Schnorr signing/verification.
#[wasm_bindgen]
pub fn hash_signable_message(msg: &[u8]) -> Vec<u8> {
    let secp_msg = libveritas::hash_signable_message(msg);
    secp_msg.as_ref().to_vec()
}

/// Verify a Schnorr signature over a message using the Spaces signed-message prefix.
#[wasm_bindgen]
pub fn verify_spaces_message(msg: &[u8], signature: &[u8], pubkey: &[u8]) -> Result<(), JsError> {
    let sig: [u8; 64] = signature.try_into()
        .map_err(|_| JsError::new("signature must be 64 bytes"))?;
    let pk: [u8; 32] = pubkey.try_into()
        .map_err(|_| JsError::new("pubkey must be 32 bytes"))?;
    libveritas::verify_spaces_message(msg, &sig, &pk)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Verify a raw Schnorr signature (no prefix, caller provides the 32-byte message hash).
#[wasm_bindgen]
pub fn verify_schnorr(msg_hash: &[u8], signature: &[u8], pubkey: &[u8]) -> Result<(), JsError> {
    let hash: [u8; 32] = msg_hash.try_into()
        .map_err(|_| JsError::new("msg_hash must be 32 bytes"))?;
    let sig: [u8; 64] = signature.try_into()
        .map_err(|_| JsError::new("signature must be 64 bytes"))?;
    let pk: [u8; 32] = pubkey.try_into()
        .map_err(|_| JsError::new("pubkey must be 32 bytes"))?;
    libveritas::verify_schnorr(&hash, &sig, &pk)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Decode stored zone bytes to a plain JS object.
#[wasm_bindgen(js_name = "decodeZone")]
pub fn decode_zone(bytes: &[u8]) -> Result<JsValue, JsError> {
    let zone = libveritas::Zone::from_slice(bytes)
        .map_err(|e| JsError::new(&format!("invalid zone: {e}")))?;
    Ok(zone_to_js(&zone))
}

/// Serialize a zone JS object to borsh bytes for storage.
#[wasm_bindgen(js_name = "zoneToBytes")]
pub fn zone_to_bytes(zone: JsValue) -> Result<Vec<u8>, JsError> {
    let inner = zone_from_js(&zone)?;
    Ok(inner.to_bytes())
}

/// Compare two zones — returns true if `a` is fresher/better than `b`.
#[wasm_bindgen(js_name = "zoneIsBetterThan")]
pub fn zone_is_better_than(a: JsValue, b: JsValue) -> Result<bool, JsError> {
    let inner_a = zone_from_js(&a)?;
    let inner_b = zone_from_js(&b)?;
    inner_a.is_better_than(&inner_b)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Decode stored certificate bytes to a JS object.
#[wasm_bindgen]
pub fn decode_certificate(bytes: &[u8]) -> Result<JsValue, JsError> {
    let cert = libveritas::cert::Certificate::from_slice(bytes)
        .map_err(|e| JsError::new(&format!("invalid certificate: {e}")))?;
    to_js(&cert)
}
