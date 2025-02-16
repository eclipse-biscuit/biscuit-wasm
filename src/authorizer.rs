use std::collections::HashMap;

use biscuit_auth as biscuit;
use serde::Deserialize;
use std::time::Duration;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{Biscuit, Check, Fact, Policy, PublicKey, Rule, Term};

#[derive(Deserialize)]
pub struct RunLimits {
    pub max_facts: Option<u64>,
    pub max_iterations: Option<u64>,
    pub max_time_micro: Option<u64>,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(20);

impl RunLimits {
    pub fn to_rust_limits(&self) -> biscuit::datalog::RunLimits {
        let defaults = biscuit::datalog::RunLimits::default();
        biscuit::datalog::RunLimits {
            max_facts: self.max_facts.unwrap_or(defaults.max_facts),
            max_iterations: self.max_iterations.unwrap_or(defaults.max_iterations),
            max_time: self
                .max_time_micro
                .map(Duration::from_micros)
                .unwrap_or(DEFAULT_TIMEOUT),
        }
    }
}

/// Creates a token
#[wasm_bindgen]
pub struct AuthorizerBuilder(pub(crate) biscuit::builder::AuthorizerBuilder);

#[wasm_bindgen]
impl AuthorizerBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> AuthorizerBuilder {
        AuthorizerBuilder(biscuit::builder::AuthorizerBuilder::new())
    }

    #[wasm_bindgen(js_name = build)]
    pub fn build(self, token: &Biscuit) -> Result<Authorizer, JsValue> {
        Ok(Authorizer(
            self.0
                .build(&token.0)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    #[wasm_bindgen(js_name = buildUnauthenticated)]
    pub fn build_unauthenticated(self) -> Result<Authorizer, JsValue> {
        Ok(Authorizer(
            self.0
                .build_unauthenticated()
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds a Datalog fact
    #[wasm_bindgen(js_name = addFact)]
    pub fn add_fact(self, fact: &Fact) -> Result<AuthorizerBuilder, JsValue> {
        Ok(AuthorizerBuilder(
            self.0
                .fact(fact.0.clone())
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds a Datalog rule
    #[wasm_bindgen(js_name = addRule)]
    pub fn add_rule(self, rule: &Rule) -> Result<AuthorizerBuilder, JsValue> {
        Ok(AuthorizerBuilder(
            self.0
                .rule(rule.0.clone())
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds a Datalog check
    #[wasm_bindgen(js_name = addCheck)]
    pub fn add_check(self, check: &Check) -> Result<AuthorizerBuilder, JsValue> {
        Ok(AuthorizerBuilder(
            self.0
                .check(check.0.clone())
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds a policy
    #[wasm_bindgen(js_name = addPolicy)]
    pub fn add_policy(self, policy: &Policy) -> Result<AuthorizerBuilder, JsValue> {
        Ok(AuthorizerBuilder(
            self.0
                .policy(policy.0.clone())
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds a code block
    #[wasm_bindgen(js_name = addCode)]
    pub fn add_code(self, source: &str) -> Result<AuthorizerBuilder, JsValue> {
        Ok(AuthorizerBuilder(
            self.0
                .code(source)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }

    /// Adds a code block with parameters
    #[wasm_bindgen(js_name = addCodeWithParameters)]
    pub fn add_code_with_parameters(
        self,
        source: &str,
        parameters: JsValue,
        scope_parameters: JsValue,
    ) -> Result<AuthorizerBuilder, JsValue> {
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

        Ok(AuthorizerBuilder(
            self.0
                .code_with_params(source, parameters, scope_parameters)
                .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?,
        ))
    }
}

/// The Authorizer verifies a request according to its policies and the provided token
#[wasm_bindgen]
//#[derive(Default)]
pub struct Authorizer(pub(crate) biscuit::Authorizer);

#[wasm_bindgen]
impl Authorizer {
    /// Runs the authorization checks and policies
    ///
    /// Returns the index of the matching allow policy, or an error containing the matching deny
    /// policy or a list of the failing checks
    #[wasm_bindgen(js_name = authorize)]
    pub fn authorize(&mut self) -> Result<usize, JsValue> {
        self.0
            .authorize_with_limits(biscuit::datalog::RunLimits {
                max_time: DEFAULT_TIMEOUT,
                ..Default::default()
            })
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = authorizeWithLimits)]
    pub fn authorize_with_limits(&mut self, limits: JsValue) -> Result<usize, JsValue> {
        let limits: RunLimits = serde_wasm_bindgen::from_value(limits)?;
        self.0
            .authorize_with_limits(limits.to_rust_limits())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// Executes a query over the authorizer
    #[wasm_bindgen(js_name = query)]
    pub fn query(&mut self, rule: &Rule) -> Result<js_sys::Array, JsValue> {
        let v: Vec<biscuit::builder::Fact> = self
            .0
            .query(rule.0.clone())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?;

        let facts = js_sys::Array::new();
        for f in v.into_iter().map(Fact) {
            facts.push(&JsValue::from(f));
        }

        Ok(facts)
    }

    /// Executes a query over the authorizer
    #[wasm_bindgen(js_name = queryWithLimits)]
    pub fn query_with_limits(
        &mut self,
        rule: &Rule,
        limits: JsValue,
    ) -> Result<js_sys::Array, JsValue> {
        let limits: RunLimits = serde_wasm_bindgen::from_value(limits)?;
        let v: Vec<biscuit::builder::Fact> = self
            .0
            .query_with_limits(rule.0.clone(), limits.to_rust_limits())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?;

        let facts = js_sys::Array::new();
        for f in v.into_iter().map(Fact) {
            facts.push(&JsValue::from(f));
        }

        Ok(facts)
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.print_world()
    }
}
