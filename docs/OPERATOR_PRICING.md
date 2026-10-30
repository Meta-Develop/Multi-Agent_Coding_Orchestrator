# Dated operator pricing for USD budgets

USD ceilings and rolling USD quotas require an applicable operator contract
before a real dispatch. A catalog placeholder or a selector cost prior cannot
establish a price. `MissingCostEstimate` preserves those limits and refuses
launch; token-only execution can retain complete tokens with unavailable cost.

Copy the fields from
[`operator-pricing.template.json`](../examples/supervise/operator-pricing.template.json)
into an authored supervisor plan. This is a field fragment, not a complete
execution plan. Its rate strings are **synthetic placeholders, not real rates**.
The template deliberately fails both rate deserialization and the
[`operator pricing schema`](../schemas/operator-pricing-plan-v1.schema.json).
Do not replace its placeholders with guessed rates or catalog zeroes.

1. Obtain a dated source applicable to the selected account and plan. Record its
   reference, attribution, contract ID, revision, effective UTC date and inclusive
   `valid_through` UTC date. References and account IDs are labels; never put
   credentials, tokens or signed URLs in a plan or report.
2. Replace each model key and scope with exact runtime, model, selected
   `account_id` and `plan_id`. Set `pricing_plan_id` to that same plan label.
   Wildcards are refused. Declare a scope for every rate-map model; each scope
   needs a matching rate. Cover every dispatched role and review lens.
3. Replace both rate strings with finite, nonnegative JSON numbers supported by
   that source. Only USD per million tokens with `flat_input_output` billing is
   supported. Explicit zero needs the same source and applicability evidence as
   nonzero rates. Cached tokens, tiers, reasoning charges, subscriptions and
   other billing dimensions need a defensible flat two-rate basis; otherwise
   leave pricing unavailable. Subscription quota is not a USD conversion.
4. Compute `pricing_contract.price_map_sha256` with the Rust
   `llm::pricing_contract::parse_price_map` and `price_map_sha256` functions.
   Hash the completed `model_pricing` object, not the entire plan. The API trims
   and sorts model keys, rejects duplicate keys, normalizes negative zero and
   serializes finite f64 rates in field order as UTF-8 JSON without a trailing
   newline. Hashing arbitrary pretty JSON can produce the wrong digest.
5. Validate the completed authored plan with `maco supervise plan plan.json
   --json` before running it with the intended USD limits. The schema checks
   structure; Rust validation additionally checks calendar dates, scope/rate
   coverage, duplicate fields, supported billing and the digest. Runtime
   admission checks the current UTC date and selected account scope.

For example, code that prepares a rate-map digest can call the public validator
without retrieving prices or contacting a provider:

```rust
use multi_agent_coding_orchestrator::llm::pricing_contract::{
    parse_price_map, price_map_sha256,
};

fn digest(rate_map_json: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let prices = parse_price_map(rate_map_json)?;
    Ok(price_map_sha256(&prices)?)
}
```

The run freezes the original contract/table bytes, normalized contract digest
and plan label in its authenticated plan snapshot. `pricing_binding` is a
retained internal binding; do not author or replace it. Resume refuses changed
inputs, mismatched bindings and expired contracts. Correct the authored inputs
and start a new run when a bound contract needs replacement. A new contract
cannot repair unpriced historical rolling-window charges: admission remains
closed while those charges are in the configured window. Inspect that history
and its window before retrying; keep the USD ceilings in place.

Budget reports retain `pricing_contract` and each charge's `pricing.basis`,
runtime, settlement model and contract identity. `normalized_sha256` binds the
contract metadata, including `price_map_sha256`. `operator_contract_estimate`
means an estimate from that contract, never a provider invoice. `synthetic`
identifies simulation; `unpriced`, `unattributed` and
`conservative_reservation` cannot establish exact priced spend. Incomplete
usage can conservatively consume a reservation while actual cost is unknown.
`cost_complete` is separate from token `usage_complete`.

Outcome costs can also retain separately observed native cost-equivalent units.
Their basis is `provider_native_cost_equivalent`; this does not supply USD
prices to the budget ledger or convert subscription quota to money.

Attempt outcome evidence and selector outcome exports retain each dispatch's
reservation ID, cost phase and pricing basis. Numeric outcome rows still require
complete attributable costs and parent acceptance evidence. Held-out evaluation
measurements copy the retained budget contract, charges and cost completeness;
profile summaries retain them per repetition and expose
`priced_cost_complete` (`null` means legacy or missing provenance). They do not
reprice usage or collapse different contract revisions into one identity.
An ambiguous observed model allocation retains tokens and unavailable cost.
Provenance does not grant production economics or acceptance eligibility.
