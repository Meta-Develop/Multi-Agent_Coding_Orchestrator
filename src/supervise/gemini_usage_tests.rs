use super::*;

fn settle_usage(
    run: &ExternalAgentRun,
    command: &ExternalAgentCommand,
) -> Result<(DispatchUsageSettlement, crate::supervise_budget::RunBudgetReport)> {
    let ledger = RunBudgetLedger::new(RunBudgetLimits {
        hard_tokens: Some(1000),
        ..Default::default()
    })?;
    let BudgetAdmission::Admitted { reservation, .. } =
        ledger.reserve(BudgetReservationRequest {
            role: AgentRole::Worker,
            tokens: 100,
            cost_usd: None,
        })?
    else {
        bail!("fixture reservation refused")
    };
    let mut reservation = DispatchBudgetReservation {
        ledger: &ledger,
        reservation,
        pricing: None,
        pricing_model: command.model.clone(),
        state: DispatchBudgetReservationState::Invoked(SupervisorRuntime::GeminiCli),
    };
    let settlement = reservation.settle_bound_runtime(run, command)?;
    Ok((settlement, ledger.report()?))
}

#[test]
fn gemini_settlement_reports_observed_model_and_never_fills_missing_usage() -> Result<()> {
    crate::external_agent::gemini_bridge::test_worker_usage_consumer(|run, command, case| {
        let (settlement, report) = settle_usage(run, command)?;
        let expected = match case {
            "complete" => DispatchUsageReliability::Reliable,
            "missing" | "forged" => DispatchUsageReliability::Missing,
            _ => DispatchUsageReliability::Estimated,
        };
        assert_eq!(settlement.reliability, expected, "{case}");
        assert_eq!(
            settlement.observed_usage.is_some(),
            matches!(case, "complete" | "mismatch" | "effort"),
            "{case}"
        );
        assert_eq!(
            settlement.model.as_deref(),
            match case {
                "complete" | "effort" => Some("gemini-2.5-pro"),
                "mismatch" => Some("gemini-2.5-flash"),
                _ => None,
            },
            "{case}"
        );
        assert_eq!(settlement.cost_usd, None);
        let sample = settlement.role_sample(AgentRole::Worker, None);
        assert_eq!(sample.is_some(), case == "complete", "{case}");
        if let Some(sample) = sample {
            assert_eq!(sample.model.as_deref(), Some("gemini-2.5-pro"));
            assert_eq!(sample.usage.total_tokens, 20);
            assert_eq!(sample.cost_usd, None);
        }
        assert_eq!(report.active_reservations, 0);
        assert_eq!(report.usage_complete, case == "complete", "{case}");
        let charge = &report.charges[0];
        assert_eq!(charge.pricing.model, settlement.model);
        assert_eq!(charge.pricing.basis, ChargePricingBasis::Unpriced);
        assert!(
            charge.tokens >= 20,
            "missing usage was coerced to zero: {case}"
        );
        assert_eq!(charge.cost_usd, None);
        if case == "complete" {
            for changed_invocation in [false, true] {
                let mut wrong = command.clone();
                if changed_invocation {
                    wrong.invocation = crate::external_agent::ExternalAgentInvocation::CodexSupervisor;
                } else {
                    wrong.model = Some("gemini-2.5-flash".into());
                }
                let (settlement, report) = settle_usage(run, &wrong)?;
                assert_eq!(settlement.reliability, DispatchUsageReliability::Estimated);
                assert!(settlement.observed_usage.is_none());
                assert!(settlement.model.is_none());
                assert!(report.charges[0].pricing.model.is_none());
                assert!(!report.usage_complete);
            }
        }
        Ok(())
    })
}
