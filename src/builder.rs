/*
 * SPDX-FileCopyrightText: 2021 Geoffroy Couprie <contact@geoffroycouprie.com>, Clément Delafargue <clement@delafargue.name>
 *
 * SPDX-License-Identifier: Apache-2.0
 */
use std::collections::{BTreeSet, HashMap};

use biscuit_auth::{self as biscuit, builder::MapKey};
use js_sys::{Array, Date, Map, Set};
use serde::{de::Visitor, Deserialize};
use time::OffsetDateTime;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{make_rng, Biscuit, PrivateKey, PublicKey};

/// Creates a token
#[wasm_bindgen]
pub struct BiscuitBuilder(pub(crate) Option<biscuit::builder::BiscuitBuilder>);

#[wasm_bindgen]
impl BiscuitBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> BiscuitBuilder {
        BiscuitBuilder(Some(biscuit::builder::BiscuitBuilder::new()))
    }

    #[wasm_bindgen(js_name = build)]
    pub fn build(mut self, root: &PrivateKey) -> Result<Biscuit, JsValue> {
        let keypair = biscuit_auth::KeyPair::from(&root.0);

        let mut rng = make_rng();
        Ok(Biscuit(
            self.0
                .take()
                .expect("empty BiscuitBuilder")
                .build_with_rng(&keypair, biscuit::datalog::SymbolTable::default(), &mut rng)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// adds the content of an existing `BlockBuilder`
    pub fn merge(&mut self, other: &BlockBuilder) {
        self.0 = Some(
            self.0
                .take()
                .expect("empty BiscuitBuilder")
                .merge(other.0.clone().expect("empty BlockBuilder")),
        );
    }

    /// Sets the root key id
    #[wasm_bindgen(js_name = setRootKeyId)]
    pub fn set_root_key_id(&mut self, root_key_id: u32) {
        self.0 = Some(
            self.0
                .take()
                .expect("empty BiscuitBuilder")
                .root_key_id(root_key_id),
        );
    }

    /// Adds a Datalog fact
    #[wasm_bindgen(js_name = addFact)]
    pub fn add_fact(&mut self, fact: &Fact) -> Result<(), JsValue> {
        self.0 = Some(
            self.0
                .take()
                .expect("empty BiscuitBuilder")
                .fact(fact.0.clone())
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        );
        Ok(())
    }

    /// Adds a Datalog rule
    #[wasm_bindgen(js_name = addRule)]
    pub fn add_rule(&mut self, rule: &Rule) -> Result<(), JsValue> {
        self.0 = Some(
            self.0
                .take()
                .expect("empty BiscuitBuilder")
                .rule(rule.0.clone())
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        );
        Ok(())
    }

    /// Adds a check
    ///
    /// All checks, from authorizer and token, must be validated to authorize the request
    #[wasm_bindgen(js_name = addCheck)]
    pub fn add_check(&mut self, check: &Check) -> Result<(), JsValue> {
        self.0 = Some(
            self.0
                .take()
                .expect("empty BiscuitBuilder")
                .check(check.0.clone())
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        );
        Ok(())
    }

    /// Adds facts, rules, checks and policies as one code block
    #[wasm_bindgen(js_name = addCode)]
    pub fn add_code(&mut self, source: &str) -> Result<(), JsValue> {
        self.0 = Some(
            self.0
                .take()
                .expect("empty BiscuitBuilder")
                .code(source)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        );
        Ok(())
    }

    /// Adds facts, rules, checks and policies as one code block
    #[wasm_bindgen(js_name = addCodeWithParameters)]
    pub fn add_code_with_parameters(
        &mut self,
        source: &str,
        parameters: JsValue,
        scope_parameters: JsValue,
    ) -> Result<(), JsValue> {
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

        self.0 = Some(
            self.0
                .take()
                .expect("empty BiscuitBuilder")
                .code_with_params(source, parameters, scope_parameters)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        );
        Ok(())
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.as_ref().expect("empty BiscuitBuilder").to_string()
    }
}

impl Default for BiscuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Creates a block to attenuate a token
#[wasm_bindgen]
#[derive(Clone)]
pub struct BlockBuilder(pub(crate) Option<biscuit::builder::BlockBuilder>);

#[wasm_bindgen]
impl BlockBuilder {
    /// creates a BlockBuilder
    ///
    /// the builder can then be given to the token's append method to create an attenuated token
    #[wasm_bindgen(constructor)]
    pub fn new() -> BlockBuilder {
        BlockBuilder(Some(biscuit::builder::BlockBuilder::new()))
    }

    /// Adds a Datalog fact
    #[wasm_bindgen(js_name = addFact)]
    pub fn add_fact(&mut self, fact: Fact) -> Result<(), JsValue> {
        self.0 = Some(
            self.0
                .take()
                .expect("empty BlockBuilder")
                .fact(fact.0)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        );
        Ok(())
    }

    /// Adds a Datalog rule
    #[wasm_bindgen(js_name = addRule)]
    pub fn add_rule(&mut self, rule: Rule) -> Result<(), JsValue> {
        self.0 = Some(
            self.0
                .take()
                .expect("empty BlockBuilder")
                .rule(rule.0)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        );
        Ok(())
    }

    /// Adds a check
    ///
    /// All checks, from authorizer and token, must be validated to authorize the request
    #[wasm_bindgen(js_name = addCheck)]
    pub fn add_check(&mut self, check: Check) -> Result<(), JsValue> {
        self.0 = Some(
            self.0
                .take()
                .expect("empty BlockBuilder")
                .check(check.0)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        );
        Ok(())
    }

    /// Adds facts, rules, checks and policies as one code block
    #[wasm_bindgen(js_name = addCode)]
    pub fn add_code(&mut self, source: &str) -> Result<(), JsValue> {
        self.0 = Some(
            self.0
                .take()
                .expect("empty BlockBuilder")
                .code(source)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        );
        Ok(())
    }

    /// Adds facts, rules, checks and policies as one code block
    #[wasm_bindgen(js_name = addCodeWithParameters)]
    pub fn add_code_with_parameters(
        &mut self,
        source: &str,
        parameters: JsValue,
        scope_parameters: JsValue,
    ) -> Result<(), JsValue> {
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

        self.0 = Some(
            self.0
                .take()
                .expect("empty BlockBuilder")
                .code_with_params(source, parameters, scope_parameters)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        );
        Ok(())
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.as_ref().expect("empty BlockBuilder").to_string()
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

    #[wasm_bindgen(js_name = terms)]
    pub fn terms(&self) -> Array {
        let array = Array::new();
        for t in self.0.predicate.terms.iter() {
            array.push(&term_to_js(t.clone()).unwrap());
        }
        array
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

fn term_to_js(value: biscuit::builder::Term) -> Result<JsValue, JsValue> {
    Ok(match value {
        biscuit::builder::Term::Integer(i) => JsValue::from_f64(i as f64),
        biscuit::builder::Term::Str(s) => JsValue::from_str(&s),
        biscuit::builder::Term::Date(d) => {
            let date = OffsetDateTime::from_unix_timestamp(d as i64).unwrap();

            // do not use the new_with_year_month_day_hr_min_sec constructor, it assumes local time
            let d = Date::new(&JsValue::undefined());
            d.set_utc_full_year_with_month_date(
                date.year() as u32,
                date.month() as i32 - 1,
                date.day() as i32,
            );
            d.set_utc_hours(date.hour() as u32);
            d.set_utc_minutes(date.minute() as u32);
            d.set_utc_seconds(date.second() as u32);
            JsValue::from(d)
        }
        biscuit::builder::Term::Bytes(items) => {
            let array = Array::new();
            for item in items {
                array.push(&JsValue::from_f64(item as f64));
            }
            JsValue::from(array)
        }
        biscuit::builder::Term::Bool(b) => JsValue::from_bool(b),
        biscuit::builder::Term::Set(btree_set) => {
            let set = Set::new(&JsValue::undefined());
            for t in btree_set {
                set.add(&term_to_js(t).unwrap());
            }
            JsValue::from(set)
        }
        biscuit::builder::Term::Null => JsValue::NULL,
        biscuit::builder::Term::Array(terms) => {
            let array = Array::new();
            for t in terms {
                array.push(&term_to_js(t).unwrap());
            }
            JsValue::from(array)
        }
        biscuit::builder::Term::Map(btree_map) => {
            let map = Map::new();
            for (k, v) in btree_map {
                let MapKey::Str(s) = k else { panic!() };
                map.set(&JsValue::from_str(&s), &term_to_js(v).unwrap());
            }
            JsValue::from(map)
        }
        biscuit::builder::Term::Variable(v) => JsValue::from_str(&v),
        biscuit::builder::Term::Parameter(p) => JsValue::from_str(&p),
    })
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
        let k: String = v
            .next_key()?
            .ok_or_else(|| Error::invalid_length(0, &self))?;
        match k.as_ref() {
            "date" => {
                let v: String = v.next_value()?;
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
                let v: String = v.next_value()?;
                let bytes = hex::decode(v)
                    .map_err(|_| Error::custom("expecting an hex-encoded byte array"))?;
                Ok(Term(biscuit::builder::Term::Bytes(bytes)))
            }
            "set" => {
                let v: Vec<Term> = v.next_value()?;
                Ok(Term(biscuit::builder::Term::Set(
                    v.into_iter().map(|t| t.0).collect(),
                )))
            }
            "map" => {
                let v: HashMap<String, Term> = v.next_value()?;
                Ok(Term(biscuit::builder::Term::Map(
                    v.into_iter()
                        .map(|(k, v)| (biscuit::builder::MapKey::Str(k), v.0))
                        .collect(),
                )))
            }

            _ => Err(Error::custom(format!(
                "unexpected key: {}, expecting date, bytes, set or map",
                &k
            ))),
        }
    }

    fn visit_seq<A>(self, mut i: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut v = Vec::new();
        let mut e: Option<Term> = i.next_element()?;
        while e.is_some() {
            v.push(e.unwrap().0);
            e = i.next_element()?;
        }
        Ok(Term(biscuit::builder::Term::Array(v)))
    }
}
