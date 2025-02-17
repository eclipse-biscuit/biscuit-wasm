// we need an explicitly defined `to_string`, and `from_str` methods
// so that we can expose them to JS with a proper name.
#![allow(clippy::inherent_to_string, clippy::should_implement_trait)]
use biscuit_auth as biscuit;
use wasm_bindgen::prelude::*;

mod authorizer;
mod builder;
mod crypto;

pub use authorizer::*;
pub use builder::*;
pub use crypto::*;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// a Biscuit token
///
/// it can produce an attenuated or sealed token, or be used
/// in an authorizer along with Datalog policies
#[wasm_bindgen]
pub struct Biscuit(biscuit::Biscuit);

#[wasm_bindgen]
impl Biscuit {
    /// Creates a BiscuitBuilder
    ///
    /// the builder can then create a new token with a root key
    pub fn builder() -> BiscuitBuilder {
        BiscuitBuilder::new()
    }

    /// Creates a BlockBuilder
    ///
    /// the builder can be merged with a `BiscuitBuilder`, another `BlockBuilder`,
    /// and used to append a block to a biscuit
    pub fn block_builder() -> BlockBuilder {
        BlockBuilder::new()
    }

    /// Creates an attenuated token by adding the block generated by the BlockBuilder
    #[wasm_bindgen(js_name = appendBlock)]
    pub fn append(&self, block: &BlockBuilder) -> Result<Biscuit, JsValue> {
        let keypair = KeyPair::new_ed25519();
        Ok(Biscuit(
            self.0
                .append_with_keypair(&keypair.0, block.0.clone().expect("empty BlockBuilder"))
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Creates an authorizer from the token
    #[wasm_bindgen(js_name = getAuthorizer)]
    pub fn authorizer(&self) -> Result<Authorizer, JsValue> {
        Ok(Authorizer(
            self.0
                .authorizer()
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Seals the token
    ///
    /// A sealed token cannot be attenuated
    #[wasm_bindgen(js_name = sealToken)]
    pub fn seal(&self) -> Result<Biscuit, JsValue> {
        Ok(Biscuit(
            self.0
                .seal()
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Deserializes a token from raw data
    ///
    /// This will check the signature using the root key
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8], root: &PublicKey) -> Result<Biscuit, JsValue> {
        Ok(Biscuit(
            biscuit::Biscuit::from(data, root.0)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Deserializes a token from URL safe base 64 data
    ///
    /// This will check the signature using the root key
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(data: &str, root: &PublicKey) -> Result<Biscuit, JsValue> {
        Ok(Biscuit(
            biscuit::Biscuit::from_base64(data, root.0)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Serializes to raw data
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Box<[u8]>, JsValue> {
        Ok(self
            .0
            .to_vec()
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?
            .into_boxed_slice())
    }

    /// Serializes to URL safe base 64 data
    #[wasm_bindgen(js_name = toBase64)]
    pub fn to_base64(&self) -> Result<String, JsValue> {
        self.0
            .to_base64()
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// Returns the list of revocation identifiers, encoded as hexadecimal strings
    #[wasm_bindgen(js_name = getRevocationIdentifiers)]
    pub fn revocation_identifiers(&self) -> Box<[JsValue]> {
        let ids: Vec<_> = self
            .0
            .revocation_identifiers()
            .into_iter()
            .map(|i| hex::encode(i).into())
            .collect();
        ids.into_boxed_slice()
    }

    /// Returns the number of blocks in the token
    #[wasm_bindgen(js_name = countBlocks)]
    pub fn block_count(&self) -> usize {
        self.0.block_count()
    }

    /// Prints a block's content as Datalog code
    #[wasm_bindgen(js_name = getBlockSource)]
    pub fn block_source(&self, index: usize) -> Result<String, JsValue> {
        self.0
            .print_block_source(index)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// Creates a third party request
    #[wasm_bindgen(js_name = getThirdPartyRequest)]
    pub fn third_party_request(&self) -> Result<ThirdPartyRequest, JsValue> {
        Ok(ThirdPartyRequest(
            self.0
                .third_party_request()
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Appends a third party block and returns a new token
    #[wasm_bindgen(js_name = appendThirdPartyBlock)]
    pub fn append_third_party(
        &self,
        external_key: &PublicKey,
        block: &ThirdPartyBlock,
    ) -> Result<Biscuit, JsValue> {
        let next_keypair = KeyPair::new_ed25519();
        Ok(Biscuit(
            self.0
                .append_third_party_with_keypair(external_key.0, block.0.clone(), next_keypair.0)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

/// Creates a block to attenuate a token
#[wasm_bindgen]
pub struct ThirdPartyRequest(biscuit::ThirdPartyRequest);

#[wasm_bindgen]
impl ThirdPartyRequest {
    /// Deserializes a third party request from raw data
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<ThirdPartyRequest, JsValue> {
        Ok(ThirdPartyRequest(
            biscuit::ThirdPartyRequest::deserialize(data)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Deserializes a third party request from URL safe base 64 data
    ///
    /// This will check the signature using the root key
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(data: &str) -> Result<ThirdPartyRequest, JsValue> {
        Ok(ThirdPartyRequest(
            biscuit::ThirdPartyRequest::deserialize_base64(data)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Serializes to raw data
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Box<[u8]>, JsValue> {
        Ok(self
            .0
            .serialize()
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?
            .into_boxed_slice())
    }

    /// Serializes to URL safe base 64 data
    #[wasm_bindgen(js_name = toBase64)]
    pub fn to_base64(&self) -> Result<String, JsValue> {
        self.0
            .serialize_base64()
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// creates a ThirdPartyBlock from a BlockBuilder and the
    /// third party service's private key
    #[wasm_bindgen(js_name = createBlock)]
    pub fn create_block(
        self,
        private_key: &PrivateKey,
        block_builder: &BlockBuilder,
    ) -> Result<ThirdPartyBlock, JsValue> {
        Ok(ThirdPartyBlock(
            self.0
                .create_block(
                    &private_key.0,
                    block_builder.0.clone().expect("empty BlockBuilder"),
                )
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }
}

#[wasm_bindgen]
pub struct ThirdPartyBlock(biscuit::ThirdPartyBlock);

#[wasm_bindgen]
impl ThirdPartyBlock {
    /// Deserializes a third party request from raw data
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<ThirdPartyRequest, JsValue> {
        Ok(ThirdPartyRequest(
            biscuit::ThirdPartyRequest::deserialize(data)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Deserializes a third party request from URL safe base 64 data
    ///
    /// This will check the signature using the root key
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(data: &str) -> Result<ThirdPartyRequest, JsValue> {
        Ok(ThirdPartyRequest(
            biscuit::ThirdPartyRequest::deserialize_base64(data)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Serializes to raw data
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Box<[u8]>, JsValue> {
        Ok(self
            .0
            .serialize()
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?
            .into_boxed_slice())
    }

    /// Serializes to URL safe base 64 data
    #[wasm_bindgen(js_name = toBase64)]
    pub fn to_base64(self) -> Result<String, JsValue> {
        self.0
            .serialize_base64()
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }
}

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    pub(crate) fn log(s: &str);
}

#[wasm_bindgen(start)]
pub fn init() {
    wasm_logger::init(wasm_logger::Config::default());
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));

    log("biscuit-wasm loading")
}
