use super::*;
use crate::llm::pricing_contract::{
    parse_price_map, price_map_sha256, OperatorPricingContract, PricingContext,
    ValidatedPricingContract,
};
use serde_json::value::RawValue;

/// Exact operator inputs retained inside the authenticated private plan snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenOperatorPricing {
    contract_json: String,
    price_map_json: String,
    plan_id: String,
    normalized_sha256: String,
}

#[derive(Deserialize)]
struct PricingFields<'a> {
    #[serde(default, borrow)]
    pricing_contract: Option<&'a RawValue>,
    #[serde(default, borrow)]
    model_pricing: Option<&'a RawValue>,
    #[serde(default)]
    pricing_plan_id: Option<String>,
    #[serde(default)]
    pricing_binding: Option<FrozenOperatorPricing>,
}

pub(super) fn load(
    contents: &str,
    plan: &mut SupervisorPlan,
) -> Result<Option<FrozenOperatorPricing>> {
    let fields: PricingFields<'_> = serde_json::from_str(contents)
        .context("supervisor pricing fields are invalid or duplicated")?;
    // Parse the original table, before Value/BTreeMap can discard duplicate keys.
    if let Some(raw) = fields.model_pricing {
        let prices = if serde_json::from_str::<Value>(raw.get())? == json!({}) {
            BTreeMap::new()
        } else {
            parse_price_map(raw.get().as_bytes()).context("model_pricing is invalid")?
        };
        plan.model_pricing = prices;
    }
    let Some(raw_contract) = fields.pricing_contract else {
        if fields.pricing_plan_id.is_some() || fields.pricing_binding.is_some() {
            bail!("pricing_plan_id and pricing_binding require pricing_contract");
        }
        return Ok(None);
    };
    let plan_id = fields
        .pricing_plan_id
        .context("pricing_contract requires an explicit pricing_plan_id")?;
    if plan_id.is_empty()
        || plan_id.trim() != plan_id
        || plan_id.chars().any(char::is_control)
        || plan_id.contains(['*', '?'])
    {
        bail!("pricing_plan_id must be an exact nonempty plan label");
    }
    let contract: OperatorPricingContract =
        serde_json::from_str(raw_contract.get()).context("pricing_contract is invalid")?;
    let validated = contract.validate(&plan.model_pricing)?;
    let input = match fields.pricing_binding {
        Some(binding) => {
            let held = binding.validated()?;
            if binding.plan_id != plan_id
                || held.contract() != validated.contract()
                || held.prices() != validated.prices()
            {
                bail!("pricing_binding does not match pricing_contract/model_pricing/plan");
            }
            binding
        }
        None => FrozenOperatorPricing {
            contract_json: raw_contract.get().to_string(),
            price_map_json: fields
                .model_pricing
                .context("pricing_contract requires model_pricing")?
                .get()
                .to_string(),
            plan_id,
            normalized_sha256: validated.content_sha256().to_string(),
        },
    };
    Ok(Some(input))
}

impl FrozenOperatorPricing {
    fn validated(&self) -> Result<ValidatedPricingContract> {
        if self.contract_json.len() as u64 > MAX_SUPERVISOR_INPUT_BYTES
            || self.price_map_json.len() as u64 > MAX_SUPERVISOR_INPUT_BYTES
        {
            bail!("frozen pricing input exceeds its byte limit");
        }
        let contract: OperatorPricingContract = serde_json::from_str(&self.contract_json)?;
        let prices = parse_price_map(self.price_map_json.as_bytes())?;
        let validated = contract.validate(&prices)?;
        if validated.content_sha256() != self.normalized_sha256 {
            bail!("frozen pricing input normalized binding changed");
        }
        Ok(validated)
    }

    pub(super) fn bind(&self, run_id: &str) -> Result<RunPricing> {
        let pricing = RunPricing {
            contract: Arc::new(self.validated()?),
            plan_id: self.plan_id.clone(),
            run_id: run_id.to_string(),
        };
        crate::budget_ledger::validate_pricing_provenance_size(&pricing.provenance())?;
        Ok(pricing)
    }

    fn require_current(&self) -> Result<()> {
        let validated = self.validated()?;
        let date = current_date()?;
        if date < validated.contract().effective_date || date > validated.contract().valid_through {
            bail!("pricing_contract is expired or not yet effective; continuation is refused");
        }
        Ok(())
    }
}

pub(super) fn write_plan_value(
    value: &mut Value,
    plan: &SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
) -> Result<()> {
    if let Some(input) = &metadata.operator_pricing {
        let validated = input.validated()?;
        if validated.prices() != &plan.model_pricing {
            bail!("model_pricing changed after pricing_contract binding");
        }
        value["pricing_contract"] = serde_json::to_value(validated.contract())?;
        value["pricing_plan_id"] = json!(input.plan_id);
        value["pricing_binding"] = serde_json::to_value(input)?;
    }
    Ok(())
}

/// Shared immutable view for run/rolling reservations and private settlement.
#[derive(Debug, Clone)]
pub(crate) struct RunPricing {
    contract: Arc<ValidatedPricingContract>,
    plan_id: String,
    run_id: String,
}

impl RunPricing {
    pub(crate) fn provenance(&self) -> PricingContractProvenance {
        PricingContractProvenance {
            contract: self.contract.contract().clone(),
            normalized_sha256: self.contract.content_sha256().to_string(),
            plan_id: self.plan_id.clone(),
        }
    }

    pub(super) fn matches_prices(&self, prices: &BTreeMap<String, ModelPricing>) -> bool {
        price_map_sha256(prices)
            .is_ok_and(|digest| digest == self.contract.contract().price_map_sha256)
    }

    pub(super) fn price_for(
        &self,
        runtime: SupervisorRuntime,
        model: &str,
    ) -> Option<ModelPricing> {
        let account_id = selected_account(&self.run_id, runtime)?;
        self.contract
            .price_for(&PricingContext {
                runtime,
                model,
                account_id: &account_id,
                plan_id: &self.plan_id,
                as_of: &current_date().ok()?,
            })
            .ok()
    }
}

fn selected_account(run_id: &str, runtime: SupervisorRuntime) -> Option<String> {
    use crate::account_authority::*;
    match runtime {
        SupervisorRuntime::Codex => match codex_run_account_binding(run_id)? {
            CodexRunAccountBinding::Selected(binding) => Some(binding.account_id),
            CodexRunAccountBinding::Missing | CodexRunAccountBinding::LocalAuth => None,
        },
        SupervisorRuntime::Grok => {
            grok_run_account_binding(run_id).map(|binding| binding.account_id)
        }
        SupervisorRuntime::ClaudeCode => {
            claude_run_account_binding(run_id).map(|binding| binding.account_id)
        }
        SupervisorRuntime::Cursor => {
            cursor_run_account_binding(run_id).map(|binding| binding.account_id)
        }
        SupervisorRuntime::GeminiCli => {
            gemini_run_account_binding(run_id).map(|binding| binding.account_id)
        }
        SupervisorRuntime::Fake => None,
    }
}

pub(super) fn missing_cost_estimate_guidance(
    runtime: SupervisorRuntime,
    command: &ExternalAgentCommand,
    ledger: &RunBudgetLedger,
) -> String {
    let model = command.model.as_deref().unwrap_or("<unresolved model>");
    let view = ledger.operator_pricing.as_ref();
    let run_id = view.map(|view| view.run_id.as_str()).or_else(|| {
        command
            .agent_lifecycle
            .as_ref()
            .map(|identity| identity.run_id.as_str())
    });
    let account = run_id.and_then(|run_id| selected_account(run_id, runtime));
    let plan_id = view.map_or("<missing pricing_plan_id>", |view| view.plan_id.as_str());
    let reason = match (view, account.as_deref(), current_date()) {
        (None, _, _) => "pricing_contract is missing or unbound".to_string(),
        (_, None, _) => "selected account scope is unavailable".to_string(),
        (Some(view), Some(account_id), Ok(date)) => view.contract.price_for(&PricingContext {
            runtime,
            model,
            account_id,
            plan_id,
            as_of: &date,
        }).map_or_else(|error| error.to_string(), |_| {
            "current scope is priced; inspect changed model_pricing, unsupported usage allocation, reservation overflow, and unpriced rolling-window history".to_string()
        }),
        (_, _, Err(_)) => "pricing applicability date is unavailable".to_string(),
    };
    format!(
        "MissingCostEstimate: runtime='{}', model='{model}', account_id='{}', pricing_plan_id='{plan_id}': {reason}. Fill authored-plan model_pricing['{model}'].input_usd_per_million_tokens and output_usd_per_million_tokens, pricing_plan_id, and pricing_contract (contract_id, revision, effective_date, valid_through, source_reference, source_attribution, currency, unit, billing, scopes with exact runtime/model/account_id/plan_id, price_map_sha256). See docs/OPERATOR_PRICING.md and examples/supervise/operator-pricing.template.json. Rolling USD admission also requires priceable history throughout its window; a new contract cannot retroactively price unknown charges. Preserve the configured USD ceilings and start a new run after correcting the inputs.",
        runtime.as_str(),
        account.as_deref().unwrap_or("<unresolved selected account>")
    )
}

fn current_date() -> Result<String> {
    Ok(
        crate::orchestration_event::format_rfc3339_utc(std::time::SystemTime::now())?[..10]
            .to_string(),
    )
}

#[cfg(test)]
pub(super) fn synthetic_input(
    plan: &SupervisorPlan,
    account_id: &str,
) -> Result<FrozenOperatorPricing> {
    let contract = OperatorPricingContract {
        schema_version: 1,
        contract_id: "synthetic-test-rates".to_string(),
        revision: "fixture-1".to_string(),
        effective_date: "2000-01-01".to_string(),
        valid_through: "9999-12-31".to_string(),
        source_reference: "urn:synthetic:test-only".to_string(),
        source_attribution: "Synthetic operator rates for tests only".to_string(),
        currency: "USD".to_string(),
        unit: "per_million_tokens".to_string(),
        billing: "flat_input_output".to_string(),
        scopes: plan
            .model_pricing
            .keys()
            .map(|model| crate::llm::pricing_contract::PricingScope {
                runtime: SupervisorRuntime::Codex,
                model: model.clone(),
                account_id: account_id.to_string(),
                plan_id: "synthetic-plan".to_string(),
            })
            .collect(),
        price_map_sha256: price_map_sha256(&plan.model_pricing)?,
    };
    Ok(FrozenOperatorPricing {
        contract_json: serde_json::to_string(&contract)?,
        price_map_json: serde_json::to_string(&plan.model_pricing)?,
        plan_id: "synthetic-plan".to_string(),
        normalized_sha256: contract
            .validate(&plan.model_pricing)?
            .content_sha256()
            .to_string(),
    })
}

#[cfg(test)]
pub(super) fn synthetic_ledger(plan: &SupervisorPlan, ledger: &mut RunBudgetLedger) {
    let run_id = format!("synthetic-pricing-{:p}", ledger);
    crate::account_authority::install_pricing_account_fixture(&run_id, "synthetic-account");
    ledger.operator_pricing = Some(
        synthetic_input(plan, "synthetic-account")
            .unwrap()
            .bind(&run_id)
            .unwrap(),
    );
}

/// Continuation authenticates the old snapshot before checking applicability.
/// A supplied caller document must retain the exact frozen bytes and plan label.
pub(super) fn verify_continuation(
    repo: &Path,
    run_id: &RunId,
    current: Option<&SupervisorPlanMetadata>,
) -> Result<()> {
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, run_id)?;
    let bytes = reader.read("assignments/supervisor-plan.json")?;
    verify_snapshot(&bytes, current)
}

pub(super) fn verify_snapshot(
    bytes: &[u8],
    current: Option<&SupervisorPlanMetadata>,
) -> Result<()> {
    let contents = std::str::from_utf8(bytes)?;
    let mut plan: SupervisorPlan = serde_json::from_str(contents)?;
    let frozen = load(contents, &mut plan)?;
    if let Some(current) = current {
        if current.operator_pricing != frozen {
            bail!("pricing contract, exact table bytes, or plan scope changed on continuation");
        }
    }
    if let Some(frozen) = frozen {
        frozen.require_current()?;
    }
    Ok(())
}
