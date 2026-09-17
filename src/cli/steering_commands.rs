use crate::{
    safe_state::BoundedRegularReader,
    steering::{SteeringDecision, SteeringOutcome, SteeringPlane, SteeringRequest},
};
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Matches `steering::control_plane::MAX_REQUEST_BODY_BYTES`.
const MAX_STEERING_REQUEST_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Args)]
pub(super) struct SteerCommand {
    #[command(subcommand)]
    command: SteerSubcommand,
}

impl SteerCommand {
    pub(super) fn run(self) -> Result<()> {
        match self.command {
            SteerSubcommand::Submit(args) => run_steering_submit(args),
            SteerSubcommand::Evidence(args) => run_steering_evidence(args),
            SteerSubcommand::Sweep(args) => run_steering_sweep(args),
        }
    }
}

#[derive(Debug, Subcommand)]
enum SteerSubcommand {
    /// Submit a typed steering request using repository-local owner authority.
    Submit(SteerSubmitArgs),
    /// Read authenticated steering evidence for one run.
    Evidence(SteerEvidenceArgs),
    /// Sweep expired steering deadlines for one run.
    Sweep(SteerSweepArgs),
}

#[derive(Debug, Args)]
struct SteerSubmitArgs {
    /// JSON steering request with explicit run, assignment, action, actor, and deadline fields.
    request: PathBuf,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SteerEvidenceArgs {
    /// Run identifier.
    run_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SteerSweepArgs {
    /// Run identifier.
    run_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn run_steering_submit(args: SteerSubmitArgs) -> Result<()> {
    let request_bytes = BoundedRegularReader::read_tree_no_follow(
        &args.request,
        MAX_STEERING_REQUEST_FILE_BYTES,
    )
    .with_context(|| format!("failed to read steering request {}", args.request.display()))?;
    let request = serde_json::from_slice::<SteeringRequest>(&request_bytes).with_context(|| {
        format!(
            "failed to parse steering request {}",
            args.request.display()
        )
    })?;
    let plane = SteeringPlane::open(&args.repo)
        .with_context(|| format!("failed to open steering plane for {}", args.repo.display()))?;
    let now_unix_ms = plane
        .current_unix_ms()
        .context("failed to read steering clock")?;
    let decision = plane
        .submit(request, now_unix_ms)
        .context("steering submit failed")?;
    print_steering_decision(&decision, args.json)?;
    finish_steering_decision(decision)
}

fn run_steering_evidence(args: SteerEvidenceArgs) -> Result<()> {
    let plane = SteeringPlane::open(&args.repo)
        .with_context(|| format!("failed to open steering plane for {}", args.repo.display()))?;
    let evidence = plane
        .evidence(&args.run_id)
        .with_context(|| format!("failed to read steering evidence for run {}", args.run_id))?;
    super::print_query_report(&evidence, args.json)
}

fn run_steering_sweep(args: SteerSweepArgs) -> Result<()> {
    let plane = SteeringPlane::open(&args.repo)
        .with_context(|| format!("failed to open steering plane for {}", args.repo.display()))?;
    let now_unix_ms = plane
        .current_unix_ms()
        .context("failed to read steering clock")?;
    let acks = plane
        .sweep(&args.run_id, now_unix_ms)
        .with_context(|| format!("failed to sweep steering deadlines for run {}", args.run_id))?;
    super::print_query_report(&acks, args.json)
}

fn print_steering_decision(decision: &SteeringDecision, json: bool) -> Result<()> {
    super::print_query_report(decision, json)
}

fn finish_steering_decision(decision: SteeringDecision) -> Result<()> {
    if let Some(refusal) = decision.refused() {
        bail!("steering refused: {}", refusal.as_str());
    }
    let ack = decision.ack();
    if ack.steered && ack.outcome != SteeringOutcome::Acknowledged {
        bail!(
            "steering reported steered=true with inconsistent outcome {:?}",
            ack.outcome
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cli::{Cli, Command},
        hierarchy_ledger::RoleCategory,
        steering::{
            AssignmentBinding, AssignmentKind, SteeringAction, SteeringActor, SteeringRequest,
            STEERING_REQUEST_VERSION,
        },
        supervise::ModelCapabilityClass,
    };
    use clap::Parser;
    use git2::Repository;
    use std::fs;

    fn init_repo() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("tempdir");
        Repository::init(temp.path()).expect("init repository");
        let path = temp.path().to_path_buf();
        (temp, path)
    }

    fn worker_binding(run_id: &str, assignment_id: &str) -> AssignmentBinding {
        AssignmentBinding {
            run_id: run_id.to_string(),
            assignment_id: assignment_id.to_string(),
            role_category: RoleCategory::NonDelegatingTerminalWorker,
            model_capability: Some(ModelCapabilityClass::WeakMechanical),
            parent_agent_id: Some("parent-1".to_string()),
            kind: AssignmentKind::Execution,
        }
    }

    fn sample_request(
        run_id: &str,
        assignment_id: &str,
        action_id: &str,
        deadline_unix_ms: u64,
    ) -> SteeringRequest {
        SteeringRequest {
            version: STEERING_REQUEST_VERSION,
            action_id: action_id.to_string(),
            run_id: run_id.to_string(),
            assignment_id: assignment_id.to_string(),
            actor: SteeringActor::Operator {
                agent_id: "operator-cli".to_string(),
            },
            action: SteeringAction::InjectCorrectiveInput {
                message: "focus on the steering CLI".to_string(),
            },
            deadline_unix_ms,
        }
    }

    fn steer_submit_args(argv: &[&str]) -> SteerSubmitArgs {
        let parsed = Cli::try_parse_from(argv).expect("steer submit arguments should parse");
        let Command::Steer(SteerCommand {
            command: SteerSubcommand::Submit(args),
        }) = parsed.command
        else {
            panic!("expected steer submit command");
        };
        args
    }

    fn steer_evidence_args(argv: &[&str]) -> SteerEvidenceArgs {
        let parsed = Cli::try_parse_from(argv).expect("steer evidence arguments should parse");
        let Command::Steer(SteerCommand {
            command: SteerSubcommand::Evidence(args),
        }) = parsed.command
        else {
            panic!("expected steer evidence command");
        };
        args
    }

    fn steer_sweep_args(argv: &[&str]) -> SteerSweepArgs {
        let parsed = Cli::try_parse_from(argv).expect("steer sweep arguments should parse");
        let Command::Steer(SteerCommand {
            command: SteerSubcommand::Sweep(args),
        }) = parsed.command
        else {
            panic!("expected steer sweep command");
        };
        args
    }

    #[test]
    fn steer_subcommands_parse_operator_shapes() {
        let submit = steer_submit_args(&[
            "maco",
            "steer",
            "submit",
            "request.json",
            "--repo",
            "my-repo",
            "--json",
        ]);
        assert_eq!(submit.request, PathBuf::from("request.json"));
        assert_eq!(submit.repo, PathBuf::from("my-repo"));
        assert!(submit.json);

        let evidence =
            steer_evidence_args(&["maco", "steer", "evidence", "run-335", "--repo", "."]);
        assert_eq!(evidence.run_id, "run-335");
        assert_eq!(evidence.repo, PathBuf::from("."));
        assert!(!evidence.json);

        let sweep = steer_sweep_args(&["maco", "steer", "sweep", "run-335"]);
        assert_eq!(sweep.run_id, "run-335");
        assert_eq!(sweep.repo, PathBuf::from("."));
    }

    #[test]
    fn steer_submit_delivers_and_records_evidence_without_steered() {
        let (_temp, repo) = init_repo();
        let plane = SteeringPlane::open(&repo).expect("open plane");
        plane
            .register_assignment(worker_binding("run-cli", "assign-cli"))
            .expect("register assignment");
        let now = plane.current_unix_ms().expect("clock");
        let request_path = repo.join("steer-request.json");
        let request = sample_request("run-cli", "assign-cli", "act-cli-1", now + 60_000);
        fs::write(
            &request_path,
            serde_json::to_vec(&request).expect("serialize request"),
        )
        .expect("write request");

        run_steering_submit(SteerSubmitArgs {
            request: request_path,
            repo: repo.clone(),
            json: false,
        })
        .expect("submit should succeed for registered assignment");

        let evidence = plane.evidence("run-cli").expect("evidence");
        assert!(
            evidence
                .iter()
                .any(|record| record.action_id == "act-cli-1" && record.event == "deliver"),
            "delivered action must appear in evidence"
        );
        assert!(
            evidence
                .iter()
                .all(|record| !record.steered || record.event == "ack"),
            "delivered evidence must not claim steered before runtime ack"
        );
    }

    #[test]
    fn steer_submit_rejects_malformed_request_json() {
        let (_temp, repo) = init_repo();
        let request_path = repo.join("broken.json");
        fs::write(&request_path, b"{not json").expect("write broken request");

        let error = run_steering_submit(SteerSubmitArgs {
            request: request_path,
            repo,
            json: false,
        })
        .expect_err("malformed request must fail");
        assert!(
            error
                .to_string()
                .contains("failed to parse steering request"),
            "{error}"
        );
    }

    #[test]
    fn steer_submit_reports_refusal_for_unknown_assignment() {
        let (_temp, repo) = init_repo();
        let plane = SteeringPlane::open(&repo).expect("open plane");
        let now = plane.current_unix_ms().expect("clock");
        let request_path = repo.join("unknown-target.json");
        let request = sample_request("run-missing", "assign-missing", "act-refused", now + 60_000);
        fs::write(
            &request_path,
            serde_json::to_vec(&request).expect("serialize request"),
        )
        .expect("write request");

        let error = run_steering_submit(SteerSubmitArgs {
            request: request_path,
            repo,
            json: false,
        })
        .expect_err("unknown assignment must refuse");
        assert!(
            error
                .to_string()
                .contains("steering refused: unknown_target"),
            "{error}"
        );
    }
}
