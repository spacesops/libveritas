use crate::cert::{Certificate, ChainProofRequestUtils};
use crate::msg::{ChainProof, Message, OffchainData};
use crate::sname::SName;
use crate::MessageError;
use spaces_ptr::ChainProofRequest;

pub struct DataUpdateRequest {
    pub handle: SName,
    pub offchain_data: Option<OffchainData>,
    pub delegate_offchain_data: Option<OffchainData>,
}

pub struct UpdateRequest {
    pub data: DataUpdateRequest,
    pub cert: Option<Certificate>,
}

pub struct MessageBuilder {
    reqs: Vec<UpdateRequest>,
}

impl MessageBuilder {
    pub fn new(reqs: Vec<UpdateRequest>) -> Self {
        Self { reqs }
    }

    /// Returns the chain proof request needed to build the message.
    ///
    /// Extracts proof keys from certificates (space, registry, commitment, sptr).
    /// For requests without a certificate, adds the minimum space-level keys.
    /// The provider/fabric expands as needed.
    pub fn chain_proof_request(&self) -> ChainProofRequest {
        let mut req = ChainProofRequest::from_certificates(
            self.reqs.iter().filter_map(|r| r.cert.as_ref()),
        );

        for update in &self.reqs {
            if update.cert.is_some() {
                continue;
            }
            let Some(space) = update.data.handle.space() else {
                continue;
            };
            req.add_space(space);
        }

        req
    }

    /// Build the message from a chain proof.
    ///
    /// Assembles certificates into bundles and sets offchain data
    /// for all requests.
    pub fn build(self, chain: ChainProof) -> Result<Message, MessageError> {
        let certs: Vec<Certificate> = self
            .reqs
            .iter()
            .filter_map(|r| r.cert.clone())
            .collect();

        let mut msg = Message::try_from_certificates(chain, certs)?;

        for update in self.reqs {
            if let Some(data) = update.data.offchain_data {
                msg.set_offchain_data(&update.data.handle, data);
            }
            if let Some(data) = update.data.delegate_offchain_data {
                msg.set_delegate_offchain_data(&update.data.handle, data);
            }
        }

        Ok(msg)
    }
}

impl Message {
    /// Update offchain data on an existing message.
    ///
    /// Construct a new message to update certificates.
    pub fn update(&mut self, updates: Vec<DataUpdateRequest>) {
        for update in updates {
            if let Some(data) = update.offchain_data {
                self.set_offchain_data(&update.handle, data);
            }
            if let Some(data) = update.delegate_offchain_data {
                self.set_delegate_offchain_data(&update.handle, data);
            }
        }
    }
}
