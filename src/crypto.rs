use std::str::FromStr;

use biscuit_auth as biscuit;
use biscuit_auth::Algorithm;
use serde::{de::Visitor, Deserialize};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

/// A pair of public and private key
#[wasm_bindgen]
pub struct KeyPair(pub(crate) biscuit::KeyPair);

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new(algorithm: SignatureAlgorithm) -> KeyPair {
        let mut rng = make_rng();

        KeyPair(biscuit::KeyPair::new_with_rng(algorithm.into(), &mut rng))
    }

    #[wasm_bindgen(js_name = fromPrivateKey)]
    pub fn from(key: &PrivateKey) -> Self {
        KeyPair(biscuit::KeyPair::from(&key.0))
    }

    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.public())
    }

    #[wasm_bindgen(js_name = getPrivateKey)]
    pub fn private(&self) -> PrivateKey {
        PrivateKey(self.0.private())
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new(SignatureAlgorithm::Ed25519)
    }
}

/// Public key
#[wasm_bindgen]
pub struct PublicKey(pub(crate) biscuit::PublicKey);

#[wasm_bindgen]
impl PublicKey {
    /// Serializes a public key to raw bytes
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self, out: &mut [u8]) -> Result<(), JsValue> {
        if out.len() != 32 {
            return Err(serde_wasm_bindgen::to_value(&biscuit::error::Token::Format(
                biscuit::error::Format::InvalidKeySize(out.len()),
            ))
            .unwrap());
        }

        out.copy_from_slice(&self.0.to_bytes());
        Ok(())
    }

    /// Serializes a public key to a hexadecimal string
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }

    /// Serializes a public key to a string usable as a datalog parameter
    #[wasm_bindgen(js_name = toDatalogParameter)]
    pub fn to_datalog_parameter(&self) -> String {
        self.to_string()
    }

    /// Deserializes a public key from raw bytes
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8], algorithm: SignatureAlgorithm) -> Result<PublicKey, JsValue> {
        let key = biscuit_auth::PublicKey::from_bytes(data, algorithm.into())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?;
        Ok(PublicKey(key))
    }

    /// Deserializes a public key from a hexadecimal string
    #[wasm_bindgen(js_name = fromString)]
    pub fn from_hex(data: &str, algorithm: SignatureAlgorithm) -> Result<PublicKey, JsValue> {
        let data = hex::decode(data).map_err(|e| {
            serde_wasm_bindgen::to_value(&biscuit::error::Token::Format(
                biscuit::error::Format::InvalidKey(format!(
                    "could not deserialize hex encoded key: {}",
                    e
                )),
            ))
            .unwrap()
        })?;
        let key = biscuit_auth::PublicKey::from_bytes(&data, algorithm.into())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?;
        Ok(PublicKey(key))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(PublicKeyVisitor)
    }
}

struct PublicKeyVisitor;

impl Visitor<'_> for PublicKeyVisitor {
    type Value = PublicKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a public key")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(s.to_string())
    }

    fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match s.strip_prefix("ed25519/") {
            Some(s) => match biscuit::PublicKey::from_bytes_hex(s, Algorithm::Ed25519) {
                Ok(pk) => Ok(PublicKey(pk)),
                Err(e) => Err(E::custom(format!("could not parse public key: {}", e))),
            },
            None => match s.strip_prefix("secp256r1/") {
                Some(s) => match biscuit::PublicKey::from_bytes_hex(s, Algorithm::Secp256r1) {
                    Ok(pk) => Ok(PublicKey(pk)),
                    Err(e) => Err(E::custom(format!("could not parse public key: {}", e))),
                },
                None => Err(E::custom(
                    "expected a public key of the format `ed25519/<hex>` or `secp256r1/<hex>`"
                        .to_string(),
                )),
            },
        }
    }
}

#[wasm_bindgen]
pub struct PrivateKey(pub(crate) biscuit::PrivateKey);

#[wasm_bindgen]
impl PrivateKey {
    /// Serializes a private key to raw bytes
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self, out: &mut [u8]) -> Result<(), JsValue> {
        if out.len() != 32 {
            return Err(serde_wasm_bindgen::to_value(&biscuit::error::Token::Format(
                biscuit::error::Format::InvalidKeySize(out.len()),
            ))
            .unwrap());
        }

        out.copy_from_slice(&self.0.to_bytes());
        Ok(())
    }

    /// Serializes a private key to a hexadecimal string
    #[wasm_bindgen(js_name = toString)]
    pub fn to_hex(&self) -> String {
        self.0.to_prefixed_string()
    }

    /// Deserializes a private key from raw bytes
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8], algorithm: SignatureAlgorithm) -> Result<PrivateKey, JsValue> {
        let key = biscuit_auth::PrivateKey::from_bytes(data, algorithm.into())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?;
        Ok(PrivateKey(key))
    }

    /// Deserializes a private key from a hexadecimal string
    #[wasm_bindgen(js_name = fromString)]
    pub fn from_hex(data: &str) -> Result<PrivateKey, JsValue> {
        let key = biscuit_auth::PrivateKey::from_str(data)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?;
        Ok(PrivateKey(key))
    }
}

#[wasm_bindgen]
#[derive(Default)]
pub enum SignatureAlgorithm {
    #[default]
    Ed25519,
    Secp256r1,
}

impl From<SignatureAlgorithm> for Algorithm {
    fn from(algorithm: SignatureAlgorithm) -> Self {
        match algorithm {
            SignatureAlgorithm::Ed25519 => Algorithm::Ed25519,
            SignatureAlgorithm::Secp256r1 => Algorithm::Secp256r1,
        }
    }
}

pub(crate) fn make_rng() -> rand::rngs::StdRng {
    let mut data = [0u8; 8];
    getrandom::getrandom(&mut data[..]).unwrap();
    rand::SeedableRng::seed_from_u64(u64::from_le_bytes(data))
}
