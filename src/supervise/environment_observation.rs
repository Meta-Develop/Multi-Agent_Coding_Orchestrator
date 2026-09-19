//! Map parent-owned account observe outcomes onto `environment_cost_microunits`.
//!
//! Unknown, stale, unavailable, and failed observations are not numeric
//! environment spend. Grok ACP token fields are not an environment signal.
//! `Some(0)` remains reserved for the proven fake/nonpublishable simulation
//! path in `outcome_history`; this helper never invents zero for a missing
//! number.

/// Parent-owned account observe outcome used to decide environment cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AccountObserveOutcomeKind {
    Unknown,
    Stale,
    Unavailable,
    Failed,
    Observed,
}

/// Attributable environment cost from a parent-owned account observation.
///
/// Non-observed kinds always yield `None`, even if a number is supplied.
/// `Observed` yields the supplied non-negative microunits, or `None` when
/// that number is missing. A missing number is never rewritten as `Some(0)`.
pub(super) fn environment_cost_microunits_from_account_observe(
    kind: AccountObserveOutcomeKind,
    observed_environment_microunits: Option<u64>,
) -> Option<u64> {
    match kind {
        AccountObserveOutcomeKind::Observed => observed_environment_microunits,
        AccountObserveOutcomeKind::Unknown
        | AccountObserveOutcomeKind::Stale
        | AccountObserveOutcomeKind::Unavailable
        | AccountObserveOutcomeKind::Failed => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_stale_unavailable_failed_stay_none() {
        for kind in [
            AccountObserveOutcomeKind::Unknown,
            AccountObserveOutcomeKind::Stale,
            AccountObserveOutcomeKind::Unavailable,
            AccountObserveOutcomeKind::Failed,
        ] {
            assert_eq!(
                environment_cost_microunits_from_account_observe(kind, None),
                None,
                "{kind:?} with a missing number must stay None"
            );
            assert_eq!(
                environment_cost_microunits_from_account_observe(kind, Some(0)),
                None,
                "{kind:?} must not copy a supplied zero into environment cost"
            );
            assert_eq!(
                environment_cost_microunits_from_account_observe(kind, Some(42)),
                None,
                "{kind:?} must ignore a supplied number"
            );
        }
    }

    #[test]
    fn observed_numeric_environment_cost_is_retained() {
        assert_eq!(
            environment_cost_microunits_from_account_observe(
                AccountObserveOutcomeKind::Observed,
                Some(12)
            ),
            Some(12)
        );
        assert_eq!(
            environment_cost_microunits_from_account_observe(
                AccountObserveOutcomeKind::Observed,
                Some(0)
            ),
            Some(0)
        );
    }

    #[test]
    fn observed_without_a_number_stays_none() {
        assert_eq!(
            environment_cost_microunits_from_account_observe(
                AccountObserveOutcomeKind::Observed,
                None
            ),
            None
        );
    }
}
