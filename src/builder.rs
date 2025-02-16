use std::collections::{BTreeSet, HashMap};

use biscuit_auth as biscuit;
use js_sys::Array;
use serde::{de::Visitor, Deserialize};
use time::OffsetDateTime;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{make_rng, Biscuit, PrivateKey, PublicKey};

/// Creates a token
#[wasm_bindgen]
pub struct BiscuitBuilder(pub(crate) biscuit::builder::BiscuitBuilder);

#[wasm_bindgen]
impl BiscuitBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> BiscuitBuilder {
        BiscuitBuilder(biscuit::builder::BiscuitBuilder::new())
    }

    #[wasm_bindgen(js_name = build)]
    pub fn build(self, root: &PrivateKey) -> Result<Biscuit, JsValue> {
        let keypair = biscuit_auth::KeyPair::from(&root.0);

        let mut rng = make_rng();
        Ok(Biscuit(
            self.0
                .build_with_rng(&keypair, biscuit::datalog::SymbolTable::default(), &mut rng)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// adds the content of an existing `BlockBuilder`
    pub fn merge(self, other: &BlockBuilder) -> Self {
        BiscuitBuilder(self.0.merge(other.0.clone()))
    }

    /// Sets the root key id
    #[wasm_bindgen(js_name = setRootKeyId)]
    pub fn set_root_key_id(self, root_key_id: u32) -> BiscuitBuilder {
        BiscuitBuilder(self.0.root_key_id(root_key_id))
    }

    /// Adds a Datalog fact
    #[wasm_bindgen(js_name = addFact)]
    pub fn add_fact(self, fact: &Fact) -> Result<BiscuitBuilder, JsValue> {
        Ok(BiscuitBuilder(
            self.0
                .fact(fact.0.clone())
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds a Datalog rule
    #[wasm_bindgen(js_name = addRule)]
    pub fn add_rule(self, rule: &Rule) -> Result<BiscuitBuilder, JsValue> {
        Ok(BiscuitBuilder(
            self.0
                .rule(rule.0.clone())
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds a check
    ///
    /// All checks, from authorizer and token, must be validated to authorize the request
    #[wasm_bindgen(js_name = addCheck)]
    pub fn add_check(self, check: &Check) -> Result<BiscuitBuilder, JsValue> {
        Ok(BiscuitBuilder(
            self.0
                .check(check.0.clone())
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds facts, rules, checks and policies as one code block
    #[wasm_bindgen(js_name = addCode)]
    pub fn add_code(self, source: &str) -> Result<BiscuitBuilder, JsValue> {
        Ok(BiscuitBuilder(
            self.0
                .code(source)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds facts, rules, checks and policies as one code block
    #[wasm_bindgen(js_name = addCodeWithParameters)]
    pub fn add_code_with_parameters(
        self,
        source: &str,
        parameters: JsValue,
        scope_parameters: JsValue,
    ) -> Result<BiscuitBuilder, JsValue> {
        let parameters: HashMap<String, Term> = serde_wasm_bindgen::from_value(parameters).unwrap();

        let parameters = parameters
            .into_iter()
            .map(|(k, t)| (k, t.0))
            .collect::<HashMap<_, _>>();

        let scope_parameters: HashMap<String, PublicKey> =
            serde_wasm_bindgen::from_value(scope_parameters).unwrap();
        let scope_parameters = scope_parameters
            .into_iter()
            .map(|(k, p)| (k, p.0))
            .collect::<HashMap<_, _>>();

        Ok(BiscuitBuilder(
            self.0
                .code_with_params(source, parameters, scope_parameters)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl Default for BiscuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Creates a block to attenuate a token
#[wasm_bindgen]
pub struct BlockBuilder(pub(crate) biscuit::builder::BlockBuilder);

#[wasm_bindgen]
impl BlockBuilder {
    /// creates a BlockBuilder
    ///
    /// the builder can then be given to the token's append method to create an attenuated token
    #[wasm_bindgen(constructor)]
    pub fn new() -> BlockBuilder {
        BlockBuilder(biscuit::builder::BlockBuilder::new())
    }

    /// Adds a Datalog fact
    #[wasm_bindgen(js_name = addFact)]
    pub fn add_fact(self, fact: Fact) -> Result<BlockBuilder, JsValue> {
        Ok(BlockBuilder(
            self.0
                .fact(fact.0)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds a Datalog rule
    #[wasm_bindgen(js_name = addRule)]
    pub fn add_rule(self, rule: Rule) -> Result<BlockBuilder, JsValue> {
        Ok(BlockBuilder(
            self.0
                .rule(rule.0)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds a check
    ///
    /// All checks, from authorizer and token, must be validated to authorize the request
    #[wasm_bindgen(js_name = addCheck)]
    pub fn add_check(self, check: Check) -> Result<BlockBuilder, JsValue> {
        Ok(BlockBuilder(
            self.0
                .check(check.0)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds facts, rules, checks and policies as one code block
    #[wasm_bindgen(js_name = addCode)]
    pub fn add_code(self, source: &str) -> Result<BlockBuilder, JsValue> {
        Ok(BlockBuilder(
            self.0
                .code(source)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds facts, rules, checks and policies as one code block
    #[wasm_bindgen(js_name = addCodeWithParameters)]
    pub fn add_code_with_parameters(
        self,
        source: &str,
        parameters: JsValue,
        scope_parameters: JsValue,
    ) -> Result<BlockBuilder, JsValue> {
        let parameters: HashMap<String, Term> = serde_wasm_bindgen::from_value(parameters).unwrap();

        let parameters = parameters
            .into_iter()
            .map(|(k, t)| (k, t.0))
            .collect::<HashMap<_, _>>();

        let scope_parameters: HashMap<String, PublicKey> =
            serde_wasm_bindgen::from_value(scope_parameters).unwrap();
        let scope_parameters = scope_parameters
            .into_iter()
            .map(|(k, p)| (k, p.0))
            .collect::<HashMap<_, _>>();

        Ok(BlockBuilder(
            self.0
                .code_with_params(source, parameters, scope_parameters)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl Default for BlockBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct Fact(pub(crate) biscuit::builder::Fact);

#[wasm_bindgen]
impl Fact {
    #[wasm_bindgen(js_name = fromString)]
    pub fn from_str(source: &str) -> Result<Fact, JsValue> {
        source
            .try_into()
            .map(Fact)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = unboundParameters)]
    pub fn unbound_parameters(&self) -> Array {
        let array = Array::new();
        for (k, v) in self.0.parameters.as_ref().unwrap_or(&HashMap::new()) {
            if v.is_none() {
                array.push(&JsValue::from_str(k));
            }
        }
        array
    }

    #[wasm_bindgen(js_name = set)]
    pub fn set(&mut self, name: &str, value: JsValue) -> Result<(), JsValue> {
        let value = js_to_term(value)?;

        self.0
            .set(name, value)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[wasm_bindgen]
pub struct Rule(pub(crate) biscuit::builder::Rule);

#[wasm_bindgen]
impl Rule {
    #[wasm_bindgen(js_name = fromString)]
    pub fn from_str(source: &str) -> Result<Rule, JsValue> {
        source
            .try_into()
            .map(Rule)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = unboundParameters)]
    pub fn unbound_parameters(&self) -> Array {
        let array = Array::new();
        for (k, v) in self.0.parameters.as_ref().unwrap_or(&HashMap::new()) {
            if v.is_none() {
                array.push(&JsValue::from_str(k));
            }
        }
        array
    }

    #[wasm_bindgen(js_name = unboundScopeParameters)]
    pub fn unbound_scope_parameters(&self) -> Array {
        let array = Array::new();
        for (k, v) in self.0.scope_parameters.as_ref().unwrap_or(&HashMap::new()) {
            if v.is_none() {
                array.push(&JsValue::from_str(k));
            }
        }
        array
    }

    #[wasm_bindgen(js_name = set)]
    pub fn set(&mut self, name: &str, value: JsValue) -> Result<(), JsValue> {
        let value = js_to_term(value)?;

        self.0
            .set(name, value)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = setScope)]
    pub fn set_scope(&mut self, name: &str, value: JsValue) -> Result<(), JsValue> {
        let value: PublicKey = serde_wasm_bindgen::from_value(value)?;

        self.0
            .set_scope(name, value.0)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[wasm_bindgen]
pub struct Check(pub(crate) biscuit::builder::Check);

#[wasm_bindgen]
impl Check {
    #[wasm_bindgen(js_name = fromString)]
    pub fn from_str(source: &str) -> Result<Check, JsValue> {
        source
            .try_into()
            .map(Check)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = unboundParameters)]
    pub fn unbound_parameters(&self) -> Array {
        let mut params = BTreeSet::new();
        let array = Array::new();
        for q in self.0.queries.iter() {
            if let Some(ps) = q.parameters.as_ref() {
                for (k, v) in ps {
                    if v.is_none() && params.insert(k.to_string()) {
                        array.push(&JsValue::from_str(k));
                    }
                }
            }
        }
        array
    }

    #[wasm_bindgen(js_name = unboundScopeParameters)]
    pub fn unbound_scope_parameters(&self) -> Array {
        let mut params = BTreeSet::new();
        let array = Array::new();
        for q in self.0.queries.iter() {
            if let Some(ps) = q.scope_parameters.as_ref() {
                for (k, v) in ps {
                    if v.is_none() && params.insert(k.to_string()) {
                        array.push(&JsValue::from_str(k));
                    }
                }
            }
        }
        array
    }

    #[wasm_bindgen(js_name = set)]
    pub fn set(&mut self, name: &str, value: JsValue) -> Result<(), JsValue> {
        let value = js_to_term(value)?;

        self.0
            .set(name, value)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = setScope)]
    pub fn set_scope(&mut self, name: &str, value: JsValue) -> Result<(), JsValue> {
        let value: PublicKey = serde_wasm_bindgen::from_value(value)?;

        self.0
            .set_scope(name, value.0)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[wasm_bindgen]
pub struct Policy(pub(crate) biscuit::builder::Policy);

#[wasm_bindgen]
impl Policy {
    #[wasm_bindgen(js_name = fromString)]
    pub fn from_str(source: &str) -> Result<Policy, JsValue> {
        source
            .try_into()
            .map(Policy)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = unboundParameters)]
    pub fn unbound_parameters(&self) -> Array {
        let mut params = BTreeSet::new();
        let array = Array::new();
        for q in self.0.queries.iter() {
            if let Some(ps) = q.parameters.as_ref() {
                for (k, v) in ps {
                    if v.is_none() && params.insert(k.to_string()) {
                        array.push(&JsValue::from_str(k));
                    }
                }
            }
        }
        array
    }

    #[wasm_bindgen(js_name = unboundScopeParameters)]
    pub fn unbound_scope_parameters(&self) -> Array {
        let mut params = BTreeSet::new();
        let array = Array::new();
        for q in self.0.queries.iter() {
            if let Some(ps) = q.scope_parameters.as_ref() {
                for (k, v) in ps {
                    if v.is_none() && params.insert(k.to_string()) {
                        array.push(&JsValue::from_str(k));
                    }
                }
            }
        }
        array
    }

    #[wasm_bindgen(js_name = set)]
    pub fn set(&mut self, name: &str, value: JsValue) -> Result<(), JsValue> {
        let value = js_to_term(value)?;

        self.0
            .set(name, value)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = setScope)]
    pub fn set_scope(&mut self, name: &str, value: JsValue) -> Result<(), JsValue> {
        let value: PublicKey = serde_wasm_bindgen::from_value(value)?;

        self.0
            .set_scope(name, value.0)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

fn js_to_term(value: JsValue) -> Result<biscuit::builder::Term, JsValue> {
    serde_wasm_bindgen::from_value(value)
        .map(|t: Term| t.0)
        .map_err(|e| serde_wasm_bindgen::to_value(&e.to_string()).unwrap())
}

pub struct Term(pub(crate) biscuit::builder::Term);

impl<'de> Deserialize<'de> for Term {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(TermVisitor)
    }
}

struct TermVisitor;

impl<'de> Visitor<'de> for TermVisitor {
    type Value = Term;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a datalog term")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Term(biscuit::builder::boolean(v)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Term(biscuit::builder::int(value)))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Term(biscuit::builder::Term::Str(v)))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Term(biscuit::builder::Term::Str(v.to_string())))
    }

    fn visit_map<A>(self, mut v: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        use serde::de::Error;
        let (k, v): (String, String) = v
            .next_entry()?
            .ok_or_else(|| Error::invalid_length(0, &self))?;
        match k.as_ref() {
            "date" => {
                let ts = OffsetDateTime::parse(
                    v.as_ref(),
                    &time::format_description::well_known::Rfc3339,
                )
                .map_err(|_| Error::custom("expecting a RFC3339-encoded date"))?;
                Ok(Term(biscuit::builder::Term::Date(
                    ts.unix_timestamp()
                        .try_into()
                        .map_err(|_| Error::custom("unix timestamp is out of range of u64"))?,
                )))
            }
            "bytes" => {
                let bytes = hex::decode(v)
                    .map_err(|_| Error::custom("expecting an hex-encoded byte array"))?;
                Ok(Term(biscuit::builder::Term::Bytes(bytes)))
            }

            _ => Err(Error::custom(format!(
                "unexpected key: {}, expecting: date",
                &k
            ))),
        }
    }

    fn visit_seq<A>(self, mut i: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut set = BTreeSet::new();
        let mut e: Option<Term> = i.next_element()?;
        while e.is_some() {
            set.insert(e.unwrap().0);
            e = i.next_element()?;
        }
        Ok(Term(biscuit::builder::Term::Set(set)))
    }
}
