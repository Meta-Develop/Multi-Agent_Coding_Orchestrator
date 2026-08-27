use anyhow::{Context, Result};
use multi_agent_coding_orchestrator::eval_harness::{
    execute_v2_local_fake, parse_manifest_v2, validate_v2_execution_results,
};

const MANIFEST: &[u8] = include_bytes!("../src/eval_harness/fixtures/issue26-manifest-v2.json");

#[test]
fn issue26_fake_operator_entrypoint_runs_end_to_end() -> Result<()> {
    let manifest = parse_manifest_v2(MANIFEST).context("parse committed issue #26 manifest")?;
    let results = execute_v2_local_fake(&manifest).context("execute deterministic fake harness")?;
    validate_v2_execution_results(&manifest, &results)
        .context("validate comparable issue #26 results")?;
    Ok(())
}
