use super::*;
use serde_json::json;

// Synthetic rates and identities exercise the contract, not a real price table.
fn fixture() -> (OperatorPricingContract, BTreeMap<String, ModelPricing>) {
    let prices = BTreeMap::from([(
        "fixture-model".to_string(),
        ModelPricing {
            input_usd_per_million_tokens: 1.0,
            output_usd_per_million_tokens: 2.0,
        },
    )]);
    let contract = OperatorPricingContract {
        schema_version: 1,
        contract_id: "fixture-contract".to_string(),
        revision: "fixture-r1".to_string(),
        effective_date: "2026-10-01".to_string(),
        valid_through: "2026-10-31".to_string(),
        source_reference: "fixture:operator-rate-card".to_string(),
        source_attribution: "Synthetic test fixture".to_string(),
        currency: "USD".to_string(),
        unit: "per_million_tokens".to_string(),
        billing: "flat_input_output".to_string(),
        scopes: vec![PricingScope {
            runtime: RuntimeId::Codex,
            model: "fixture-model".to_string(),
            account_id: "fixture-account".to_string(),
            plan_id: "fixture-plan".to_string(),
        }],
        price_map_sha256: price_map_sha256(&prices).unwrap(),
    };
    (contract, prices)
}

fn context() -> PricingContext<'static> {
    PricingContext {
        runtime: RuntimeId::Codex,
        model: "fixture-model",
        account_id: "fixture-account",
        plan_id: "fixture-plan",
        as_of: "2026-10-29",
    }
}

fn rejects_contract(
    change: impl FnOnce(&mut OperatorPricingContract),
    expected: PricingUnavailable,
) {
    let (mut contract, prices) = fixture();
    change(&mut contract);
    assert_eq!(contract.validate(&prices).unwrap_err(), expected);
}

#[test]
fn dated_contract_requires_source_scope_and_valid_rates() {
    let (mut contract, mut prices) = fixture();
    assert_eq!(
        resolve_operator_pricing(Some(&contract), &prices, &context()).unwrap(),
        prices["fixture-model"]
    );
    prices.values_mut().for_each(|price| {
        price.input_usd_per_million_tokens = 0.0;
        price.output_usd_per_million_tokens = 0.0;
    });
    contract.price_map_sha256 = price_map_sha256(&prices).unwrap();
    let zero = resolve_operator_pricing(Some(&contract), &prices, &context()).unwrap();
    assert_eq!(zero.input_usd_per_million_tokens, 0.0);
    assert_eq!(zero.output_usd_per_million_tokens, 0.0);

    rejects_contract(
        |contract| contract.schema_version = 2,
        PricingUnavailable::UnsupportedVersion(2),
    );
    for field in [
        "contract_id",
        "revision",
        "source_reference",
        "source_attribution",
    ] {
        let (contract, prices) = fixture();
        let mut value = serde_json::to_value(contract).unwrap();
        value[field] = json!("");
        let contract: OperatorPricingContract = serde_json::from_value(value).unwrap();
        assert_eq!(
            contract.validate(&prices).unwrap_err(),
            PricingUnavailable::InvalidText(field)
        );
    }
    rejects_contract(
        |contract| contract.source_reference = " source ".to_string(),
        PricingUnavailable::InvalidText("source_reference"),
    );
    rejects_contract(
        |contract| contract.source_attribution = "source\nextra".to_string(),
        PricingUnavailable::InvalidText("source_attribution"),
    );
    for (field, value) in [
        ("currency", "EUR"),
        ("unit", "per_token"),
        ("billing", "cached_input"),
        ("billing", "tiered"),
        ("billing", "separate_reasoning"),
        ("billing", "subscription_quota"),
    ] {
        let (contract, prices) = fixture();
        let mut wire = serde_json::to_value(contract).unwrap();
        wire[field] = json!(value);
        let contract: OperatorPricingContract = serde_json::from_value(wire).unwrap();
        assert_eq!(
            contract.validate(&prices).unwrap_err(),
            PricingUnavailable::UnsupportedBasis(field)
        );
    }
    for invalid in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        for input in [true, false] {
            let (contract, mut prices) = fixture();
            let rate = prices.get_mut("fixture-model").unwrap();
            if input {
                rate.input_usd_per_million_tokens = invalid;
            } else {
                rate.output_usd_per_million_tokens = invalid;
            }
            assert_eq!(
                contract.validate(&prices).unwrap_err(),
                PricingUnavailable::InvalidRates("fixture-model".to_string())
            );
        }
    }
}

#[test]
fn strict_contract_and_price_map_reject_unknown_or_duplicate_fields() {
    let (contract, _) = fixture();
    let original = serde_json::to_value(&contract).unwrap();
    let mut extra = original.clone();
    extra["extra"] = json!(true);
    assert!(serde_json::from_value::<OperatorPricingContract>(extra).is_err());
    let mut extra = original.clone();
    extra["scopes"][0]["extra"] = json!(true);
    assert!(serde_json::from_value::<OperatorPricingContract>(extra).is_err());
    let mut invalid_runtime = original.clone();
    invalid_runtime["scopes"][0]["runtime"] = json!("*");
    assert!(serde_json::from_value::<OperatorPricingContract>(invalid_runtime).is_err());
    for field in ["source_reference", "scopes", "price_map_sha256"] {
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<OperatorPricingContract>(missing).is_err());
    }
    let encoded = serde_json::to_string(&contract).unwrap();
    let duplicate = format!(r#"{{"schema_version":1,{}"#, &encoded[1..]);
    assert!(serde_json::from_str::<OperatorPricingContract>(&duplicate).is_err());

    let row = r#"{"input_usd_per_million_tokens":1.0,"output_usd_per_million_tokens":2.0}"#;
    let valid = format!(r#"{{" fixture-model ":{row}}}"#);
    assert!(parse_price_map(valid.as_bytes())
        .unwrap()
        .contains_key("fixture-model"));
    for extra in [
        "cached_input_usd_per_million_tokens",
        "tier",
        "reasoning_rate",
    ] {
        let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
        value[" fixture-model "][extra] = json!(0);
        assert!(parse_price_map(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    for keys in [
        r#""fixture-model","fixture-model""#,
        r#""fixture-model"," fixture-model ""#,
    ] {
        let (first, second) = keys.split_once(',').unwrap();
        let duplicate = format!("{{{first}:{row},{second}:{row}}}");
        assert!(parse_price_map(duplicate.as_bytes()).is_err());
    }
    let duplicate_rate = br#"{"fixture-model":{"input_usd_per_million_tokens":1,"input_usd_per_million_tokens":0,"output_usd_per_million_tokens":2}}"#;
    assert!(parse_price_map(duplicate_rate).is_err());
    for invalid in [b"{}".as_slice(), b"null", b"[]", b"{} trailing"] {
        assert!(parse_price_map(invalid).is_err());
    }
}

#[test]
fn normalized_digest_binds_exact_rates_without_key_or_zero_ambiguity() {
    let (contract, prices) = fixture();
    let padded = BTreeMap::from([(" fixture-model ".to_string(), prices["fixture-model"])]);
    assert_eq!(
        price_map_sha256(&padded).unwrap(),
        contract.price_map_sha256
    );
    assert_eq!(contract.validate(&padded).unwrap().prices(), &prices);
    let mut duplicate = padded;
    duplicate.insert("fixture-model".to_string(), prices["fixture-model"]);
    assert_eq!(
        normalize_price_map(&duplicate).unwrap_err(),
        PricingUnavailable::DuplicateModel("fixture-model".to_string())
    );
    for model in ["", "  ", "fixture\nmodel", "fixture-*", "fixture-?"] {
        let invalid = BTreeMap::from([(model.to_string(), prices["fixture-model"])]);
        assert!(matches!(
            normalize_price_map(&invalid),
            Err(PricingUnavailable::InvalidModel(_))
        ));
    }
    let mut negative_zero = prices.clone();
    negative_zero
        .get_mut("fixture-model")
        .unwrap()
        .input_usd_per_million_tokens = -0.0;
    let mut positive_zero = negative_zero.clone();
    positive_zero
        .get_mut("fixture-model")
        .unwrap()
        .input_usd_per_million_tokens = 0.0;
    assert_eq!(
        price_map_sha256(&negative_zero).unwrap(),
        price_map_sha256(&positive_zero).unwrap()
    );
    let mut changed = prices.clone();
    changed
        .get_mut("fixture-model")
        .unwrap()
        .output_usd_per_million_tokens = 3.0;
    assert_eq!(
        contract.validate(&changed).unwrap_err(),
        PricingUnavailable::DigestMismatch
    );
    rejects_contract(
        |contract| contract.price_map_sha256 = "not-a-digest".to_string(),
        PricingUnavailable::InvalidDigest,
    );
    rejects_contract(
        |contract| contract.price_map_sha256 = "A".repeat(64),
        PricingUnavailable::InvalidDigest,
    );
}

#[test]
fn dates_use_real_calendar_and_inclusive_utc_validity_bounds() {
    let (contract, prices) = fixture();
    let validated = contract.validate(&prices).unwrap();
    for as_of in ["2026-10-01", "2026-10-31"] {
        let mut context = context();
        context.as_of = as_of;
        assert!(validated.price_for(&context).is_ok());
    }
    for (as_of, expected) in [
        ("2026-09-30", PricingUnavailable::NotYetEffective),
        ("2026-11-01", PricingUnavailable::Expired),
        ("2026-02-30", PricingUnavailable::InvalidDate("as_of")),
    ] {
        let mut context = context();
        context.as_of = as_of;
        assert_eq!(validated.price_for(&context).unwrap_err(), expected);
    }
    for date in ["2024-02-29", "2000-02-29", "2400-02-29", "0001-01-01"] {
        let mut contract = contract.clone();
        contract.effective_date = date.to_string();
        contract.valid_through = date.to_string();
        assert!(contract.validate(&prices).is_ok());
    }
    for date in [
        "2026-02-29",
        "1900-02-29",
        "2100-02-29",
        "2026-04-31",
        "0000-01-01",
        "2026-00-01",
        "2026-13-01",
        "2026-01-00",
        "2026-1-01",
        "2026-01-01T00:00:00Z",
        "２０２６-01-01",
    ] {
        rejects_contract(
            |contract| contract.effective_date = date.to_string(),
            PricingUnavailable::InvalidDate("effective_date"),
        );
    }
    rejects_contract(
        |contract| contract.valid_through = "2026-02-30".to_string(),
        PricingUnavailable::InvalidDate("valid_through"),
    );
    rejects_contract(
        |contract| contract.valid_through = "2026-09-30".to_string(),
        PricingUnavailable::InvalidValidityWindow,
    );
}

#[test]
fn scopes_require_exact_covered_runtime_model_account_and_plan() {
    let (contract, prices) = fixture();
    let validated = contract.validate(&prices).unwrap();
    let mut wrong_runtime = context();
    wrong_runtime.runtime = RuntimeId::Grok;
    let mut wrong_model = context();
    wrong_model.model = "other-fixture-model";
    let mut wrong_account = context();
    wrong_account.account_id = "other-account";
    let mut wrong_plan = context();
    wrong_plan.plan_id = "other-plan";
    let mut padded_model = context();
    padded_model.model = " fixture-model ";
    for wrong in [
        wrong_runtime,
        wrong_model,
        wrong_account,
        wrong_plan,
        padded_model,
    ] {
        assert_eq!(
            validated.price_for(&wrong).unwrap_err(),
            PricingUnavailable::ScopeMismatch
        );
    }
    rejects_contract(
        |contract| contract.scopes.clear(),
        PricingUnavailable::EmptyScopes,
    );
    rejects_contract(
        |contract| contract.scopes.push(contract.scopes[0].clone()),
        PricingUnavailable::DuplicateScope,
    );
    rejects_contract(
        |contract| contract.scopes[0].account_id.clear(),
        PricingUnavailable::InvalidText("scope.account_id"),
    );
    rejects_contract(
        |contract| contract.scopes[0].plan_id = "*".to_string(),
        PricingUnavailable::WildcardScope,
    );
    rejects_contract(
        |contract| contract.scopes[0].model = "missing-model".to_string(),
        PricingUnavailable::UnpricedScope("missing-model".to_string()),
    );
    let mut extra = prices.clone();
    extra.insert("extra-model".to_string(), prices["fixture-model"]);
    assert_eq!(
        contract.validate(&extra).unwrap_err(),
        PricingUnavailable::MissingScope("extra-model".to_string())
    );
}

#[test]
fn immutable_view_binds_provenance_and_rechecks_expiry() {
    let (mut contract, mut prices) = fixture();
    let frozen = contract.validate(&prices).unwrap();
    let original_rate = frozen.price_for(&context()).unwrap();
    for field in [
        "source_reference",
        "source_attribution",
        "revision",
        "contract_id",
    ] {
        let mut changed = serde_json::to_value(&contract).unwrap();
        changed[field] = json!("changed-fixture");
        let changed: OperatorPricingContract = serde_json::from_value(changed).unwrap();
        assert_ne!(
            changed.validate(&prices).unwrap().content_sha256(),
            frozen.content_sha256()
        );
    }
    contract.scopes.push(PricingScope {
        account_id: "second-fixture-account".to_string(),
        ..contract.scopes[0].clone()
    });
    let ordered = contract.validate(&prices).unwrap();
    contract.scopes.reverse();
    assert_eq!(
        contract.validate(&prices).unwrap().content_sha256(),
        ordered.content_sha256()
    );
    prices
        .get_mut("fixture-model")
        .unwrap()
        .input_usd_per_million_tokens = 4.0;
    assert_eq!(
        contract.validate(&prices).unwrap_err(),
        PricingUnavailable::DigestMismatch
    );
    contract.price_map_sha256 = price_map_sha256(&prices).unwrap();
    assert_ne!(
        contract.validate(&prices).unwrap().content_sha256(),
        ordered.content_sha256()
    );
    assert_eq!(frozen.price_for(&context()).unwrap(), original_rate);
    assert_eq!(frozen.contract().revision, "fixture-r1");
    let mut expired = context();
    expired.as_of = "2026-11-01";
    assert_eq!(
        frozen.price_for(&expired).unwrap_err(),
        PricingUnavailable::Expired
    );
}

#[test]
fn missing_contract_or_unknown_identity_never_uses_catalog_prices() {
    let (contract, prices) = fixture();
    assert_eq!(
        resolve_operator_pricing(None, &prices, &context()).unwrap_err(),
        PricingUnavailable::MissingContract
    );
    assert_eq!(
        contract.validate(&BTreeMap::new()).unwrap_err(),
        PricingUnavailable::EmptyPriceMap
    );
    for model in ["fake", "gpt-6.1-sol", "unknown-model"] {
        let mut context = context();
        context.model = model;
        assert_eq!(
            resolve_operator_pricing(Some(&contract), &prices, &context).unwrap_err(),
            PricingUnavailable::ScopeMismatch
        );
    }
}
