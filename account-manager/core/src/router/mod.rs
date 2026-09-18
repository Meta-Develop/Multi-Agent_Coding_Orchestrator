//! Ordered, account-aware request routing (FR-7).
//!
//! This module performs no I/O. The relay supplies configured account targets,
//! M4 quota results, the current time, and any observed rate-limit deadline.
//! A request can be served only from the [`RouteSelection`] returned here.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::model::{ProviderQuotaList, QuotaListOutcome, QuotaSnapshot, RouteRule};

/// Non-secret account identity attached to a relay target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAccount {
    pub provider_id: String,
    pub account_id: String,
}

/// The only router output from which the relay may choose an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSelection {
    pub rule_index: usize,
    pub provider_id: String,
    pub account_id: String,
    pub target_model: String,
    /// Latest applicable provider-published reset strictly after selection.
    /// The relay may use it when an observed rate-limit response has no usable
    /// `Retry-After` value.
    pub quota_resets_at: Option<OffsetDateTime>,
}

/// Public rule field names for secret-free validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRuleField {
    MatchModel,
    ProviderId,
    TargetModel,
    MaxUtilization,
}

/// Routing failures contain positions and categories, never submitted values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    InvalidRule {
        rule_index: usize,
        field: RouteRuleField,
    },
    MissingRouteAccount {
        rule_index: usize,
    },
    DuplicateRouteAccounts {
        rule_index: usize,
    },
    InvalidRouteAccount {
        rule_index: usize,
    },
    UnmatchedModel,
    NoEligibleRoute,
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRule { rule_index, field } => write!(
                formatter,
                "routing rule {rule_index} has an invalid {}",
                field.as_str()
            ),
            Self::MissingRouteAccount { rule_index } => {
                write!(
                    formatter,
                    "routing rule {rule_index} has no configured account"
                )
            }
            Self::DuplicateRouteAccounts { rule_index } => write!(
                formatter,
                "routing rule {rule_index} resolves to more than one account"
            ),
            Self::InvalidRouteAccount { rule_index } => write!(
                formatter,
                "routing rule {rule_index} resolves to an invalid account"
            ),
            Self::UnmatchedModel => formatter.write_str("no routing rule matches the model"),
            Self::NoEligibleRoute => {
                formatter.write_str("matching routing rules have no eligible account")
            }
        }
    }
}

impl StdError for RouteError {}

impl RouteRuleField {
    fn as_str(self) -> &'static str {
        match self {
            Self::MatchModel => "model pattern",
            Self::ProviderId => "provider id",
            Self::TargetModel => "target model",
            Self::MaxUtilization => "quota ceiling",
        }
    }
}

/// In-memory account throttle state. It is deliberately not serializable.
#[derive(Debug, Default)]
pub struct RouterState {
    throttled_until: HashMap<(String, String), OffsetDateTime>,
}

impl RouterState {
    /// Select the first eligible matching rule at or after `start_index`.
    ///
    /// Rules are always validated as a complete document before evaluation.
    /// A matching rule must resolve to exactly one configured account; an
    /// absent or ambiguous account is a configuration error and cannot cause
    /// fallback. Quota and an observed account throttle are the only
    /// pre-request conditions that skip an otherwise matching valid rule.
    pub fn select_next(
        &mut self,
        rules: &[RouteRule],
        accounts: &[RouteAccount],
        quotas: &[ProviderQuotaList],
        inbound_model: &str,
        start_index: usize,
        now: OffsetDateTime,
    ) -> Result<RouteSelection, RouteError> {
        validate_rules(rules)?;
        self.throttled_until.retain(|_, until| *until > now);

        let any_pattern_matches = rules
            .iter()
            .any(|rule| model_matches(&rule.match_model, inbound_model));

        for (rule_index, rule) in rules.iter().enumerate().skip(start_index) {
            if !model_matches(&rule.match_model, inbound_model) {
                continue;
            }

            let account = resolve_account(rule_index, &rule.provider_id, accounts)?;
            if self.is_throttled(account, now) {
                continue;
            }

            let quota = applicable_quota(
                quotas,
                &rule.provider_id,
                &account.account_id,
                &rule.target_model,
                now,
            );
            if rule
                .max_utilization
                .is_some_and(|ceiling| quota.is_none_or(|quota| quota.utilization > ceiling))
            {
                continue;
            }

            return Ok(RouteSelection {
                rule_index,
                provider_id: rule.provider_id.clone(),
                account_id: account.account_id.clone(),
                target_model: rule.target_model.clone(),
                quota_resets_at: quota.and_then(|quota| quota.resets_at),
            });
        }

        if any_pattern_matches {
            Err(RouteError::NoEligibleRoute)
        } else {
            Err(RouteError::UnmatchedModel)
        }
    }

    /// Record only an observed rate-limit deadline for the selected account.
    /// A repeated observation may extend, but never shorten, the throttle.
    pub fn record_rate_limit(&mut self, selection: &RouteSelection, until: OffsetDateTime) {
        let key = (selection.provider_id.clone(), selection.account_id.clone());
        self.throttled_until
            .entry(key)
            .and_modify(|current| *current = (*current).max(until))
            .or_insert(until);
    }

    /// Return the recorded deadline for an account, including an expired one
    /// that has not yet been pruned by a selection call.
    pub fn throttle_until(&self, provider_id: &str, account_id: &str) -> Option<OffsetDateTime> {
        self.throttled_until
            .get(&(provider_id.to_owned(), account_id.to_owned()))
            .copied()
    }

    fn is_throttled(&self, account: &RouteAccount, now: OffsetDateTime) -> bool {
        self.throttled_until
            .get(&(account.provider_id.clone(), account.account_id.clone()))
            .is_some_and(|until| *until > now)
    }
}

/// Validate the whole ordered rule document before it can spend any quota.
pub fn validate_rules(rules: &[RouteRule]) -> Result<(), RouteError> {
    for (rule_index, rule) in rules.iter().enumerate() {
        if rule.match_model.trim().is_empty() || !valid_pattern(&rule.match_model) {
            return Err(RouteError::InvalidRule {
                rule_index,
                field: RouteRuleField::MatchModel,
            });
        }
        if rule.provider_id.trim().is_empty() {
            return Err(RouteError::InvalidRule {
                rule_index,
                field: RouteRuleField::ProviderId,
            });
        }
        if rule.target_model.trim().is_empty() {
            return Err(RouteError::InvalidRule {
                rule_index,
                field: RouteRuleField::TargetModel,
            });
        }
        if rule
            .max_utilization
            .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        {
            return Err(RouteError::InvalidRule {
                rule_index,
                field: RouteRuleField::MaxUtilization,
            });
        }
    }
    Ok(())
}

fn valid_pattern(pattern: &str) -> bool {
    let stars = pattern.bytes().filter(|byte| *byte == b'*').count();
    stars == 0 || (stars == 1 && pattern.ends_with('*'))
}

fn model_matches(pattern: &str, inbound_model: &str) -> bool {
    pattern.strip_suffix('*').map_or_else(
        || pattern == inbound_model,
        |prefix| inbound_model.starts_with(prefix),
    )
}

fn resolve_account<'a>(
    rule_index: usize,
    provider_id: &str,
    accounts: &'a [RouteAccount],
) -> Result<&'a RouteAccount, RouteError> {
    let mut matches = accounts
        .iter()
        .filter(|account| account.provider_id == provider_id);
    let account = matches
        .next()
        .ok_or(RouteError::MissingRouteAccount { rule_index })?;
    if matches.next().is_some() {
        return Err(RouteError::DuplicateRouteAccounts { rule_index });
    }
    if account.account_id.trim().is_empty() {
        return Err(RouteError::InvalidRouteAccount { rule_index });
    }
    Ok(account)
}

#[derive(Clone, Copy)]
struct ApplicableQuota {
    utilization: f32,
    resets_at: Option<OffsetDateTime>,
}

fn applicable_quota(
    quotas: &[ProviderQuotaList],
    provider_id: &str,
    account_id: &str,
    target_model: &str,
    now: OffsetDateTime,
) -> Option<ApplicableQuota> {
    let mut providers = quotas
        .iter()
        .filter(|quota| quota.provider_id == provider_id);
    let provider = providers.next()?;
    if providers.next().is_some() || !matches!(provider.outcome, QuotaListOutcome::Available) {
        return None;
    }
    if provider
        .snapshots
        .iter()
        .any(|snapshot| !valid_snapshot(snapshot))
    {
        return None;
    }

    let applicable: Vec<_> = provider
        .snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.account_id == account_id
                && snapshot
                    .model
                    .as_deref()
                    .is_none_or(|model| model == target_model)
        })
        .collect();
    if applicable.is_empty() {
        return None;
    }

    let utilization = applicable
        .iter()
        .map(|snapshot| snapshot.utilization)
        .fold(0.0_f32, f32::max);
    let resets_at = applicable
        .iter()
        .filter_map(|snapshot| snapshot.resets_at.as_deref())
        .filter_map(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .filter(|reset| *reset > now)
        .max();
    Some(ApplicableQuota {
        utilization,
        resets_at,
    })
}

fn valid_snapshot(snapshot: &QuotaSnapshot) -> bool {
    snapshot.utilization.is_finite()
        && (0.0..=1.0).contains(&snapshot.utilization)
        && OffsetDateTime::parse(&snapshot.captured_at, &Rfc3339).is_ok()
        && snapshot
            .resets_at
            .as_deref()
            .is_none_or(|value| OffsetDateTime::parse(value, &Rfc3339).is_ok())
}
