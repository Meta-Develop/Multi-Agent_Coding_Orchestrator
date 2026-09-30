//! Verified Gemini execution binding to CAM `gemini-cli` selected-account authority.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use coding_agent_manager_lib::account_authority::{
    authority_id_for, SelectedAccountBinding, SelectedUseLease, StoredAccountRegistry,
};
use coding_agent_manager_lib::error::Error as CamError;
use coding_agent_manager_lib::paths::{project_dirs, stored_accounts_path};
use coding_agent_manager_lib::providers::gemini_cli::GeminiCliAdapter;
use coding_agent_manager_lib::providers::{launch_spec_for, LaunchSpec};

pub(crate) use super::GEMINI_CLI_PROVIDER_ID;
use super::{
    configured_cam_authority_socket, require_carried_gemini_launch_binding,
    FrozenGeminiSelectedBinding, ManagedGeminiAccountSelectionEvidence,
};

const GOOGLE_GENAI_USE_GCA: &str = "GOOGLE_GENAI_USE_GCA";

/// Frozen CAM selection, active use lease, and validated managed Gemini home.
pub(crate) struct GeminiLaunchAuthority {
    registry: StoredAccountRegistry,
    binding: SelectedAccountBinding,
    authority_id: Option<String>,
    socket_bound: bool,
    _selected_use_lease: SelectedUseLease,
    managed_gemini_home: PathBuf,
    launch_env_removals: Vec<String>,
}

impl GeminiLaunchAuthority {
    pub(crate) fn selection_evidence(&self) -> ManagedGeminiAccountSelectionEvidence {
        ManagedGeminiAccountSelectionEvidence {
            provider_id: self.binding.provider_id.clone(),
            account_id: self.binding.account_id.clone(),
            account_incarnation: self.binding.account_incarnation.clone(),
            selection_revision: self.binding.selection_revision,
            authority_id: self.authority_id.clone(),
        }
    }

    pub(crate) fn managed_gemini_home(&self) -> &Path {
        &self.managed_gemini_home
    }

    pub(crate) fn apply_launch_environment(&self, environment: &mut BTreeMap<String, String>) {
        for name in &self.launch_env_removals {
            environment.remove(name);
        }
        environment.insert(GOOGLE_GENAI_USE_GCA.to_string(), "true".to_string());
    }

    /// Re-read both socket and registry identities immediately before child release.
    pub(crate) fn verify_binding_unchanged(&self) -> Result<()> {
        if self.socket_bound {
            let socket_path = configured_cam_authority_socket().ok_or_else(|| {
                anyhow!(
                    "Coding Agent Manager authority socket is no longer configured; refusing local fallback"
                )
            })?;
            let live = super::selected_binding_via_authority_socket(
                &socket_path,
                GEMINI_CLI_PROVIDER_ID,
            )
            .context(
                "failed to revalidate Coding Agent Manager Gemini selection via authority socket",
            )?;
            let Some((authority_id, binding)) = live else {
                return Err(anyhow!(
                    "no complete account is selected for Coding Agent Manager provider `{GEMINI_CLI_PROVIDER_ID}`"
                ));
            };
            if self
                .authority_id
                .as_ref()
                .is_some_and(|expected| expected != &authority_id)
            {
                return Err(anyhow!(
                    "Coding Agent Manager authority identity does not match the frozen Gemini authority"
                ));
            }
            if binding != self.binding {
                return Err(map_binding_drift(&self.binding, &binding));
            }
        }
        let current = self
            .registry
            .selected_binding(GEMINI_CLI_PROVIDER_ID)
            .context("failed to read Coding Agent Manager Gemini selection")?
            .ok_or_else(|| {
                anyhow!(
                    "no complete account is selected for Coding Agent Manager provider `{GEMINI_CLI_PROVIDER_ID}`"
                )
            })?;
        if current != self.binding {
            return Err(map_binding_drift(&self.binding, &current));
        }
        if let Some(expected) = &self.authority_id {
            if authority_id_for(self.registry.metadata_path()) != *expected {
                return Err(anyhow!(
                    "Coding Agent Manager execution authority does not match the frozen Gemini authority"
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn acquire_gemini_launch_authority(
    carried: Option<&FrozenGeminiSelectedBinding>,
) -> Result<GeminiLaunchAuthority> {
    let socket_path = configured_cam_authority_socket();
    let frozen = require_carried_gemini_launch_binding(carried, socket_path.is_some())?;
    if let Some(socket_path) = socket_path.as_ref() {
        let frozen = frozen.context(
            "no frozen Gemini selection binding from Coding Agent Manager authority socket observation",
        )?;
        revalidate_frozen_selection_via_socket(socket_path, frozen)?;
        return acquire_from_execution_registry(Some(frozen), true);
    }
    acquire_from_execution_registry(frozen, false)
}

fn revalidate_frozen_selection_via_socket(
    socket_path: &Path,
    frozen: &FrozenGeminiSelectedBinding,
) -> Result<()> {
    let expected_authority = frozen.authority_id.as_deref().context(
        "frozen Gemini selection is missing authority identity for the configured CAM socket",
    )?;
    let live = super::selected_binding_via_authority_socket(socket_path, GEMINI_CLI_PROVIDER_ID)
        .context(
            "failed to revalidate Coding Agent Manager Gemini selection via authority socket",
        )?;
    let Some((authority_id, binding)) = live else {
        return Err(anyhow!(
            "no complete account is selected for Coding Agent Manager provider `{GEMINI_CLI_PROVIDER_ID}` via authority socket"
        ));
    };
    if authority_id != expected_authority {
        return Err(anyhow!(
            "Coding Agent Manager authority identity does not match the frozen Gemini authority"
        ));
    }
    if !frozen.matches_selected_binding(&binding) {
        return Err(map_binding_drift(&frozen.to_selected_binding(), &binding));
    }
    Ok(())
}

fn acquire_from_execution_registry(
    frozen: Option<&FrozenGeminiSelectedBinding>,
    socket_bound: bool,
) -> Result<GeminiLaunchAuthority> {
    let data_dir = project_dirs()
        .map(|dirs| dirs.data_dir().to_path_buf())
        .context(
            "Coding Agent Manager data directory is unavailable; install or configure the manager",
        )?;
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data_dir));
    let current = registry
        .selected_binding(GEMINI_CLI_PROVIDER_ID)
        .context("failed to read Coding Agent Manager Gemini selection")?
        .ok_or_else(|| {
            anyhow!(
                "no complete account is selected for Coding Agent Manager provider `{GEMINI_CLI_PROVIDER_ID}`"
            )
        })?;
    let (binding, authority_id) = if let Some(frozen) = frozen {
        require_execution_matches_frozen(frozen, &registry, &current)?;
        (frozen.to_selected_binding(), frozen.authority_id.clone())
    } else {
        (current, None)
    };
    finish_gemini_launch_authority(
        &registry,
        &GeminiCliAdapter::default(),
        binding,
        authority_id,
        socket_bound,
    )
}

fn require_execution_matches_frozen(
    frozen: &FrozenGeminiSelectedBinding,
    registry: &StoredAccountRegistry,
    current: &SelectedAccountBinding,
) -> Result<()> {
    if let Some(expected) = &frozen.authority_id {
        if authority_id_for(registry.metadata_path()) != *expected {
            return Err(anyhow!(
                "Coding Agent Manager execution authority does not match the frozen Gemini authority"
            ));
        }
    }
    if !frozen.matches_selected_binding(current) {
        return Err(map_binding_drift(&frozen.to_selected_binding(), current));
    }
    Ok(())
}

fn finish_gemini_launch_authority(
    registry: &StoredAccountRegistry,
    adapter: &GeminiCliAdapter,
    binding: SelectedAccountBinding,
    authority_id: Option<String>,
    socket_bound: bool,
) -> Result<GeminiLaunchAuthority> {
    let selected_use_lease = registry
        .acquire_selected_use(&binding)
        .map_err(map_cam_error)?;
    let account = registry
        .complete(GEMINI_CLI_PROVIDER_ID, &binding.account_id)
        .map_err(map_cam_error)?;
    let launch_spec = launch_spec_for(adapter, &account).map_err(map_cam_error)?;
    let managed_gemini_home = gemini_home_from_launch_spec(&launch_spec)?;
    let launch_env_removals = launch_spec.environment_removals();
    if launch_env_removals
        .iter()
        .any(|name| name == GOOGLE_GENAI_USE_GCA)
    {
        return Err(anyhow!(
            "Coding Agent Manager Gemini launch spec removed its required GCA binding"
        ));
    }
    Ok(GeminiLaunchAuthority {
        registry: StoredAccountRegistry::new(registry.metadata_path()),
        binding,
        authority_id,
        socket_bound,
        _selected_use_lease: selected_use_lease,
        managed_gemini_home,
        launch_env_removals,
    })
}

fn gemini_home_from_launch_spec(spec: &LaunchSpec) -> Result<PathBuf> {
    let plain_environment = spec.plain_environment();
    let homes = plain_environment
        .iter()
        .filter(|(name, _)| name == "GEMINI_CLI_HOME")
        .map(|(_, value)| PathBuf::from(value.as_os_str()))
        .collect::<Vec<_>>();
    let gca = plain_environment
        .iter()
        .filter(|(name, value)| {
            name == GOOGLE_GENAI_USE_GCA && value.as_os_str() == OsStr::new("true")
        })
        .count();
    match (plain_environment.len(), homes.as_slice(), gca) {
        (2, [home], 1) if home.is_absolute() => Ok(home.clone()),
        _ => Err(anyhow!(
            "Coding Agent Manager Gemini launch spec must declare exactly one absolute GEMINI_CLI_HOME and GOOGLE_GENAI_USE_GCA=true"
        )),
    }
}

fn map_binding_drift(
    expected: &SelectedAccountBinding,
    current: &SelectedAccountBinding,
) -> anyhow::Error {
    if current.selection_revision != expected.selection_revision {
        return anyhow!("Coding Agent Manager selection for `{GEMINI_CLI_PROVIDER_ID}` is stale");
    }
    if current.account_incarnation != expected.account_incarnation {
        return anyhow!(
            "Coding Agent Manager account `{}` no longer matches the requested incarnation",
            expected.account_id
        );
    }
    if current.account_id != expected.account_id {
        return anyhow!(
            "Coding Agent Manager account `{}` is not the selected account",
            expected.account_id
        );
    }
    anyhow!("Coding Agent Manager selection for `{GEMINI_CLI_PROVIDER_ID}` is stale")
}

fn map_cam_error(error: CamError) -> anyhow::Error {
    match error {
        CamError::NoSelectedAccount(provider) => anyhow!(
            "no complete account is selected for Coding Agent Manager provider `{provider}`"
        ),
        CamError::StaleSelection { provider } => {
            anyhow!("Coding Agent Manager selection for `{provider}` is stale")
        }
        CamError::StaleAccount { account_id } => anyhow!(
            "Coding Agent Manager account `{account_id}` no longer matches the requested incarnation"
        ),
        CamError::UnknownAccount(account_id) => {
            anyhow!("Coding Agent Manager account `{account_id}` is not registered")
        }
        CamError::AccountAuthorityBusy { reason } => {
            anyhow!("Coding Agent Manager account authority is busy: {reason}")
        }
        CamError::CredentialStoreUnavailable(reason) => {
            anyhow!("Coding Agent Manager credential store is unavailable: {reason}")
        }
        CamError::ConfigRead { provider, reason } => anyhow!(
            "Coding Agent Manager configuration for `{provider}` could not be read: {reason}"
        ),
        CamError::ConfigWrite { provider, reason } => anyhow!(
            "Coding Agent Manager configuration for `{provider}` could not be written: {reason}"
        ),
        CamError::UnknownProvider(provider) => {
            anyhow!("Coding Agent Manager provider `{provider}` is not registered")
        }
        CamError::ProviderNotInstalled { provider } => {
            anyhow!("Coding Agent Manager provider `{provider}` is not installed on this machine")
        }
        CamError::NotImplemented(feature) => {
            anyhow!("Coding Agent Manager does not implement `{feature}` yet")
        }
        CamError::Io(error) => error.into(),
        CamError::Serde(error) => error.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};

    fn add_complete(registry: &StoredAccountRegistry, account_id: &str) {
        registry
            .begin_add(
                GEMINI_CLI_PROVIDER_ID,
                account_id,
                account_id,
                AuthKind::OAuth,
                StoredAccountMaterial::VendorHome,
            )
            .expect("begin synthetic Gemini account");
        registry
            .complete_add(GEMINI_CLI_PROVIDER_ID, account_id)
            .expect("complete synthetic Gemini account");
    }

    #[test]
    fn gemini_launch_authority_retains_selected_use_lease_until_drop() {
        let temp = tempfile::tempdir().expect("tempdir");
        let metadata = stored_accounts_path(temp.path());
        let registry = StoredAccountRegistry::new(&metadata);
        add_complete(&registry, "work");
        add_complete(&registry, "personal");
        let binding = registry
            .select_complete_revision(GEMINI_CLI_PROVIDER_ID, "work", None)
            .expect("select work");
        let lease = registry
            .acquire_selected_use(&binding)
            .expect("selected-use lease");
        let authority = GeminiLaunchAuthority {
            registry: StoredAccountRegistry::new(&metadata),
            binding,
            authority_id: None,
            socket_bound: false,
            _selected_use_lease: lease,
            managed_gemini_home: temp.path().join("managed-home"),
            launch_env_removals: vec!["GOOGLE_APPLICATION_CREDENTIALS".to_string()],
        };
        let mut environment = BTreeMap::from([
            (
                "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                "ambient".to_string(),
            ),
            ("HOME".to_string(), "/private".to_string()),
        ]);
        authority.apply_launch_environment(&mut environment);
        assert!(!environment.contains_key("GOOGLE_APPLICATION_CREDENTIALS"));
        assert_eq!(
            environment.get(GOOGLE_GENAI_USE_GCA).map(String::as_str),
            Some("true")
        );
        let busy = registry
            .select_complete_revision(GEMINI_CLI_PROVIDER_ID, "personal", None)
            .expect_err("authority must retain selected-use lease");
        assert!(matches!(busy, CamError::AccountAuthorityBusy { .. }));
        drop(authority);
        registry
            .select_complete_revision(GEMINI_CLI_PROVIDER_ID, "personal", None)
            .expect("selection may change after authority drop");
    }

    #[test]
    fn gemini_launch_spec_requires_exact_home_and_gca_binding() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("managed-home");
        let missing_gca =
            LaunchSpec::new("gemini").set_plain_env("GEMINI_CLI_HOME", home.as_os_str());
        assert!(gemini_home_from_launch_spec(&missing_gca).is_err());

        let valid = LaunchSpec::new("gemini")
            .set_plain_env("GEMINI_CLI_HOME", home.as_os_str())
            .set_plain_env(GOOGLE_GENAI_USE_GCA, "true");
        assert_eq!(
            gemini_home_from_launch_spec(&valid).expect("exact OAuth launch environment"),
            home
        );

        let extra = LaunchSpec::new("gemini")
            .set_plain_env("GEMINI_CLI_HOME", home.as_os_str())
            .set_plain_env(GOOGLE_GENAI_USE_GCA, "true")
            .set_plain_env("UNEXPECTED", "value");
        assert!(gemini_home_from_launch_spec(&extra).is_err());
    }

    #[test]
    fn gemini_binding_drift_distinguishes_revision_incarnation_and_account() {
        let expected = SelectedAccountBinding {
            provider_id: GEMINI_CLI_PROVIDER_ID.to_string(),
            account_id: "work".to_string(),
            account_incarnation: "inc-work".to_string(),
            selection_revision: 7,
        };
        let mut current = expected.clone();
        current.selection_revision = 8;
        assert!(map_binding_drift(&expected, &current)
            .to_string()
            .contains("stale"));
        current = expected.clone();
        current.account_incarnation = "inc-replaced".to_string();
        assert!(map_binding_drift(&expected, &current)
            .to_string()
            .contains("incarnation"));
        current = expected.clone();
        current.account_id = "personal".to_string();
        assert!(map_binding_drift(&expected, &current)
            .to_string()
            .contains("not the selected account"));
    }
}
