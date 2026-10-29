//! Pure validation of operator-supplied flat token prices and their applicability.
//!
//! No prices, clock, account discovery, or source retrieval are supplied here.
//! A validated contract describes an estimate, not an invoice or quota conversion.
//! Runtime admission and frozen-run integration remain the caller's responsibility.

use super::provider::ModelPricing;
use crate::{artifacts::state_auth::sha256_hex, runtime_adapter::RuntimeId};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;

pub const OPERATOR_PRICING_CONTRACT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorPricingContract {
    pub schema_version: u32,
    pub contract_id: String,
    pub revision: String,
    pub effective_date: String,
    /// Inclusive UTC calendar date, in YYYY-MM-DD format.
    pub valid_through: String,
    pub source_reference: String,
    pub source_attribution: String,
    pub currency: String,
    pub unit: String,
    /// Only `flat_input_output` is supported. Cache, tier and other billing
    /// dimensions require evidence that the two-rate table cannot represent.
    pub billing: String,
    pub scopes: Vec<PricingScope>,
    /// SHA-256 of the normalized, exact operator `model_pricing` map.
    pub price_map_sha256: String,
}

/// An exact applicability tuple. Identifiers are labels, never credentials.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PricingScope {
    pub runtime: RuntimeId,
    pub model: String,
    pub account_id: String,
    pub plan_id: String,
}

pub struct PricingContext<'a> {
    pub runtime: RuntimeId,
    /// Callers must supply an authenticated, unambiguous usage identity.
    pub model: &'a str,
    pub account_id: &'a str,
    pub plan_id: &'a str,
    /// Trusted UTC calendar date supplied by the caller at each use.
    pub as_of: &'a str,
}

/// Immutable rates and provenance; this type cannot be deserialized unchecked.
#[derive(Debug, Clone)]
pub struct ValidatedPricingContract {
    contract: OperatorPricingContract,
    prices: BTreeMap<String, ModelPricing>,
    content_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PricingUnavailable {
    #[error("pricing_contract metadata is missing")]
    MissingContract,
    #[error("unsupported pricing_contract schema version {0}")]
    UnsupportedVersion(u32),
    #[error("pricing_contract {0} must be nonempty, trimmed text without control characters")]
    InvalidText(&'static str),
    #[error("pricing_contract {0} must be a valid YYYY-MM-DD calendar date")]
    InvalidDate(&'static str),
    #[error("pricing_contract valid_through precedes effective_date")]
    InvalidValidityWindow,
    #[error("unsupported pricing_contract {0}; only USD, per_million_tokens, flat_input_output pricing is supported")]
    UnsupportedBasis(&'static str),
    #[error("model_pricing must contain explicit rates")]
    EmptyPriceMap,
    #[error("invalid model_pricing key '{0}'")]
    InvalidModel(String),
    #[error("model_pricing has duplicate model '{0}' after trimming")]
    DuplicateModel(String),
    #[error("model_pricing for '{0}' must contain finite nonnegative rates")]
    InvalidRates(String),
    #[error("pricing_contract must declare at least one exact applicability scope")]
    EmptyScopes,
    #[error("pricing_contract scope identifiers cannot contain wildcards")]
    WildcardScope,
    #[error("pricing_contract contains a duplicate applicability scope")]
    DuplicateScope,
    #[error("pricing_contract scope has no model_pricing entry for '{0}'")]
    UnpricedScope(String),
    #[error("model_pricing entry '{0}' has no pricing_contract scope")]
    MissingScope(String),
    #[error("pricing_contract price_map_sha256 must be 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("pricing_contract price_map_sha256 does not match normalized model_pricing")]
    DigestMismatch,
    #[error("pricing_contract is not yet effective")]
    NotYetEffective,
    #[error("pricing_contract has expired")]
    Expired,
    #[error("no pricing_contract scope matches runtime/model/account/plan exactly")]
    ScopeMismatch,
    #[error("pricing_contract serialization failed: {0}")]
    Serialization(String),
}

/// Read a rate map without silently accepting duplicate keys or extra billing
/// fields. The returned map uses the same trimmed keys as authored plans.
pub fn parse_price_map(bytes: &[u8]) -> Result<BTreeMap<String, ModelPricing>, serde_json::Error> {
    struct PriceMap(BTreeMap<String, ModelPricing>);
    impl<'de> Deserialize<'de> for PriceMap {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> de::Visitor<'de> for Visitor {
                type Value = PriceMap;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("an explicit model_pricing map with unique model keys")
                }

                fn visit_map<A: de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<PriceMap, A::Error> {
                    let mut prices = BTreeMap::new();
                    while let Some((model, pricing)) = map.next_entry::<String, ModelPricing>()? {
                        let model = model.trim().to_string();
                        if prices.insert(model.clone(), pricing).is_some() {
                            return Err(de::Error::custom(PricingUnavailable::DuplicateModel(
                                model,
                            )));
                        }
                    }
                    normalize_price_map(&prices)
                        .map(PriceMap)
                        .map_err(de::Error::custom)
                }
            }
            deserializer.deserialize_map(Visitor)
        }
    }
    serde_json::from_slice::<PriceMap>(bytes).map(|map| map.0)
}

pub fn normalize_price_map(
    prices: &BTreeMap<String, ModelPricing>,
) -> Result<BTreeMap<String, ModelPricing>, PricingUnavailable> {
    if prices.is_empty() {
        return Err(PricingUnavailable::EmptyPriceMap);
    }
    let mut normalized = BTreeMap::new();
    for (model, pricing) in prices {
        let model = model.trim();
        if model.is_empty() || model.chars().any(char::is_control) || model.contains(['*', '?']) {
            return Err(PricingUnavailable::InvalidModel(model.to_string()));
        }
        if !pricing.is_valid() {
            return Err(PricingUnavailable::InvalidRates(model.to_string()));
        }
        let mut pricing = *pricing;
        // Both IEEE zero representations denote the same explicit rate.
        if pricing.input_usd_per_million_tokens == 0.0 {
            pricing.input_usd_per_million_tokens = 0.0;
        }
        if pricing.output_usd_per_million_tokens == 0.0 {
            pricing.output_usd_per_million_tokens = 0.0;
        }
        if normalized.insert(model.to_string(), pricing).is_some() {
            return Err(PricingUnavailable::DuplicateModel(model.to_string()));
        }
    }
    Ok(normalized)
}

/// Canonical JSON object with sorted, trimmed model keys, struct field order,
/// finite f64 rates, and positive zero; hashed as UTF-8 without a trailing LF.
pub fn price_map_sha256(
    prices: &BTreeMap<String, ModelPricing>,
) -> Result<String, PricingUnavailable> {
    content_sha256(&normalize_price_map(prices)?)
}

impl OperatorPricingContract {
    pub fn validate(
        &self,
        prices: &BTreeMap<String, ModelPricing>,
    ) -> Result<ValidatedPricingContract, PricingUnavailable> {
        if self.schema_version != OPERATOR_PRICING_CONTRACT_SCHEMA_VERSION {
            return Err(PricingUnavailable::UnsupportedVersion(self.schema_version));
        }
        for (field, text) in [
            ("contract_id", self.contract_id.as_str()),
            ("revision", &self.revision),
            ("source_reference", &self.source_reference),
            ("source_attribution", &self.source_attribution),
        ] {
            validate_text(field, text)?;
        }
        validate_date("effective_date", &self.effective_date)?;
        validate_date("valid_through", &self.valid_through)?;
        if self.valid_through < self.effective_date {
            return Err(PricingUnavailable::InvalidValidityWindow);
        }
        for (field, actual, supported) in [
            ("currency", self.currency.as_str(), "USD"),
            ("unit", &self.unit, "per_million_tokens"),
            ("billing", &self.billing, "flat_input_output"),
        ] {
            if actual != supported {
                return Err(PricingUnavailable::UnsupportedBasis(field));
            }
        }
        let prices = normalize_price_map(prices)?;
        if self.scopes.is_empty() {
            return Err(PricingUnavailable::EmptyScopes);
        }
        for (index, scope) in self.scopes.iter().enumerate() {
            for (field, text) in [
                ("scope.model", scope.model.as_str()),
                ("scope.account_id", &scope.account_id),
                ("scope.plan_id", &scope.plan_id),
            ] {
                validate_text(field, text)?;
                if text.contains(['*', '?']) {
                    return Err(PricingUnavailable::WildcardScope);
                }
            }
            if self.scopes[..index].contains(scope) {
                return Err(PricingUnavailable::DuplicateScope);
            }
            if !prices.contains_key(&scope.model) {
                return Err(PricingUnavailable::UnpricedScope(scope.model.clone()));
            }
        }
        for model in prices.keys() {
            if !self.scopes.iter().any(|scope| scope.model == *model) {
                return Err(PricingUnavailable::MissingScope(model.clone()));
            }
        }
        if self.price_map_sha256.len() != 64
            || !self
                .price_map_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PricingUnavailable::InvalidDigest);
        }
        if self.price_map_sha256 != content_sha256(&prices)? {
            return Err(PricingUnavailable::DigestMismatch);
        }
        let mut contract = self.clone();
        contract.scopes.sort_by(|left, right| {
            (
                left.runtime.as_str(),
                &left.model,
                &left.account_id,
                &left.plan_id,
            )
                .cmp(&(
                    right.runtime.as_str(),
                    &right.model,
                    &right.account_id,
                    &right.plan_id,
                ))
        });
        Ok(ValidatedPricingContract {
            content_sha256: content_sha256(&contract)?,
            contract,
            prices,
        })
    }
}

impl ValidatedPricingContract {
    pub fn contract(&self) -> &OperatorPricingContract {
        &self.contract
    }

    pub fn prices(&self) -> &BTreeMap<String, ModelPricing> {
        &self.prices
    }

    /// Binds all metadata and, through price_map_sha256, every normalized rate.
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    /// Recheck the date and exact scope on each use; never fall back to catalog
    /// placeholders, requested identity, another account, or another plan.
    pub fn price_for(
        &self,
        context: &PricingContext<'_>,
    ) -> Result<ModelPricing, PricingUnavailable> {
        validate_date("as_of", context.as_of)?;
        if context.as_of < self.contract.effective_date.as_str() {
            return Err(PricingUnavailable::NotYetEffective);
        }
        if context.as_of > self.contract.valid_through.as_str() {
            return Err(PricingUnavailable::Expired);
        }
        if !self.contract.scopes.iter().any(|scope| {
            scope.runtime == context.runtime
                && scope.model == context.model
                && scope.account_id == context.account_id
                && scope.plan_id == context.plan_id
        }) {
            return Err(PricingUnavailable::ScopeMismatch);
        }
        self.prices
            .get(context.model)
            .copied()
            .ok_or_else(|| PricingUnavailable::UnpricedScope(context.model.to_string()))
    }
}

pub fn resolve_operator_pricing(
    contract: Option<&OperatorPricingContract>,
    prices: &BTreeMap<String, ModelPricing>,
    context: &PricingContext<'_>,
) -> Result<ModelPricing, PricingUnavailable> {
    contract
        .ok_or(PricingUnavailable::MissingContract)?
        .validate(prices)?
        .price_for(context)
}

fn content_sha256(value: &impl Serialize) -> Result<String, PricingUnavailable> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| PricingUnavailable::Serialization(error.to_string()))
}

fn validate_text(field: &'static str, text: &str) -> Result<(), PricingUnavailable> {
    if text.is_empty() || text.trim() != text || text.chars().any(char::is_control) {
        return Err(PricingUnavailable::InvalidText(field));
    }
    Ok(())
}

fn validate_date(field: &'static str, date: &str) -> Result<(), PricingUnavailable> {
    let invalid = || PricingUnavailable::InvalidDate(field);
    let bytes = date.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    let year: u32 = date[..4].parse().map_err(|_| invalid())?;
    let month: u32 = date[5..7].parse().map_err(|_| invalid())?;
    let day: u32 = date[8..].parse().map_err(|_| invalid())?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(invalid()),
    };
    if year == 0 || day == 0 || day > days {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
