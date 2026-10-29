use super::*;

impl AssignmentMetadata {
    pub(super) fn executor(
        &self,
        assignment_id: &str,
        worker_id: Option<&str>,
    ) -> ExecutorSelection {
        self.executors
            .get(&(assignment_id.to_string(), worker_id.map(str::to_string)))
            .cloned()
            .unwrap_or_default()
    }
}

pub(super) fn parse_assignment_executor(
    raw: &Value,
    assignment_id: &str,
    worker_id: Option<&str>,
    metadata: &mut AssignmentMetadata,
) -> Result<()> {
    let Some(raw_executor) = raw.get("executor") else {
        return Ok(());
    };
    let selection: ExecutorSelection =
        serde_json::from_value(raw_executor.clone()).with_context(|| {
            format!(
                "assignment '{}' executor is invalid",
                worker_id.unwrap_or(assignment_id)
            )
        })?;
    if let Some(target) = selection.ssh_target() {
        crate::executor::SshConfig::validate_target_identity(
            target.host_id.as_str(),
            target.endpoint.as_str(),
            target.user.as_str(),
            target.port.get(),
        )
        .context("invalid supervised SSH target identity")?;
    }
    // Canonicalize explicit Local to omission so existing plan/checkpoint bindings
    // remain stable. A typed remote declaration is retained, never rewritten Local.
    if selection != ExecutorSelection::Local {
        metadata.executors.insert(
            (assignment_id.to_string(), worker_id.map(str::to_string)),
            selection,
        );
    }
    Ok(())
}

pub(super) fn serialize_assignment_executor(
    value: &mut Value,
    assignment_id: &str,
    worker_id: Option<&str>,
    metadata: &AssignmentMetadata,
) -> Result<()> {
    let selection = metadata.executor(assignment_id, worker_id);
    if selection != ExecutorSelection::Local {
        value
            .as_object_mut()
            .context("normalized assignment is not an object")?
            .insert("executor".into(), serde_json::to_value(selection)?);
    }
    Ok(())
}

pub(super) fn validate_assignment_executors_pre_dispatch(
    metadata: &AssignmentMetadata,
) -> Result<()> {
    for ((assignment_id, worker_id), selection) in &metadata.executors {
        if let Some(target) = selection.ssh_target() {
            bail!(
                "assignment '{}' SSH target '{}' is unknown or untrusted for supervised execution: \
                 no authenticated target binding or production executor bridge is configured; \
                 refusing before launch without Local fallback",
                worker_id.as_deref().unwrap_or(assignment_id),
                target.host_id.as_str()
            );
        }
    }
    Ok(())
}
