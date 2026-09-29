//! Selected CAM Claude OAuth authority held for one managed native launch.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use coding_agent_manager_lib::account_authority::{
    authority_id_for, SelectedAccountBinding, SelectedUseLease, StoredAccountRegistry,
};
use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};
use coding_agent_manager_lib::paths::{project_dirs, stored_accounts_path};
use coding_agent_manager_lib::storage::Secret;
use serde::de::{Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::artifacts::state_auth::sha256_hex;

use super::{
    configured_cam_authority_socket, require_carried_claude_launch_binding,
    FrozenClaudeSelectedBinding, CLAUDE_CODE_PROVIDER_ID,
};

const MAX_CLAUDE_CREDENTIAL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedClaudeAccountSelectionEvidence {
    pub provider_id: String,
    pub account_id: String,
    pub account_incarnation: String,
    pub selection_revision: u64,
    pub authority_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    length: u64,
    modified: Option<SystemTime>,
    digest: String,
}

/// Frozen selection, use lease, managed vendor home, and one in-memory OAuth grant.
pub(crate) struct ClaudeLaunchAuthority {
    registry: StoredAccountRegistry,
    binding: SelectedAccountBinding,
    authority_id: Option<String>,
    socket_bound: bool,
    _selected_use_lease: SelectedUseLease,
    #[cfg(test)]
    managed_home: PathBuf,
    managed_data_root: PathBuf,
    child_config_home: tempfile::TempDir,
    credential_path: PathBuf,
    credential_file: File,
    credential_identity: CredentialIdentity,
    oauth_expires_at_unix_millis: u64,
    oauth_grant: Option<Secret>,
    child_oauth_grant: Option<Secret>,
}

impl ClaudeLaunchAuthority {
    pub(crate) fn selection_evidence(&self) -> ManagedClaudeAccountSelectionEvidence {
        ManagedClaudeAccountSelectionEvidence {
            provider_id: self.binding.provider_id.clone(),
            account_id: self.binding.account_id.clone(),
            account_incarnation: self.binding.account_incarnation.clone(),
            selection_revision: self.binding.selection_revision,
            authority_id: self.authority_id.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn managed_home(&self) -> &Path {
        &self.managed_home
    }

    pub(crate) fn managed_data_root(&self) -> &Path {
        &self.managed_data_root
    }

    pub(crate) fn child_config_home(&self) -> &Path {
        self.child_config_home.path()
    }

    pub(crate) fn account_binding_string(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.authority_id.as_deref().unwrap_or("local-registry"),
            self.binding.provider_id,
            self.binding.account_id,
            self.binding.account_incarnation,
            self.binding.selection_revision
        )
    }

    pub(crate) fn take_oauth_grant(&mut self) -> Result<Secret> {
        self.oauth_grant
            .take()
            .context("Claude OAuth grant was already consumed for this launch")
    }

    pub(crate) fn take_child_oauth_grant(&mut self) -> Result<Secret> {
        self.child_oauth_grant
            .take()
            .context("Claude child OAuth grant was already consumed for this launch")
    }

    pub(crate) fn oauth_grant_bytes(&self) -> Result<&[u8]> {
        self.oauth_grant
            .as_ref()
            .map(Secret::expose)
            .context("Claude OAuth grant was already consumed for this launch")
    }

    pub(crate) fn apply_launch_environment(&self, environment: &mut BTreeMap<String, String>) {
        for name in [
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_SECURESTORAGE_CONFIG_DIR",
        ] {
            environment.remove(name);
        }
        environment.insert(
            "CLAUDE_CONFIG_DIR".to_string(),
            self.child_config_home.path().to_string_lossy().into_owned(),
        );
    }

    pub(crate) fn verify_binding_unchanged(&mut self) -> Result<()> {
        if self.socket_bound {
            let socket_path = configured_cam_authority_socket().ok_or_else(|| {
                anyhow!(
                    "Coding Agent Manager authority socket is no longer configured; refusing local fallback"
                )
            })?;
            let live =
                super::selected_binding_via_authority_socket(&socket_path, CLAUDE_CODE_PROVIDER_ID)
                    .context("failed to revalidate Coding Agent Manager Claude selection")?;
            let Some((authority_id, binding)) = live else {
                bail!("no complete selected Coding Agent Manager Claude account");
            };
            if self.authority_id.as_deref() != Some(authority_id.as_str())
                || binding != self.binding
            {
                bail!("Coding Agent Manager Claude selection changed after reservation");
            }
        }
        let current = self
            .registry
            .selected_binding(CLAUDE_CODE_PROVIDER_ID)
            .context("failed to read Coding Agent Manager Claude selection")?
            .context("no complete selected Coding Agent Manager Claude account")?;
        if current != self.binding {
            bail!("Coding Agent Manager Claude selection changed after reservation");
        }
        if let Some(expected) = &self.authority_id {
            if authority_id_for(self.registry.metadata_path()) != *expected {
                bail!("Coding Agent Manager Claude authority identity changed after reservation");
            }
        }
        verify_credential_source(
            &mut self.credential_file,
            &self.credential_path,
            &self.credential_identity,
        )?;
        if self.oauth_expires_at_unix_millis <= now_unix_millis()? {
            bail!("managed Claude OAuth access token expired while the launch was held");
        }
        Ok(())
    }
}

pub(crate) fn acquire_claude_launch_authority(
    carried: Option<&FrozenClaudeSelectedBinding>,
    deadline_unix_millis: u64,
) -> Result<ClaudeLaunchAuthority> {
    let socket_path = configured_cam_authority_socket();
    let frozen = require_carried_claude_launch_binding(carried, socket_path.is_some())?;
    if let (Some(socket_path), Some(frozen)) = (socket_path.as_ref(), frozen) {
        let live =
            super::selected_binding_via_authority_socket(socket_path, CLAUDE_CODE_PROVIDER_ID)
                .context("failed to revalidate Coding Agent Manager Claude selection")?;
        let Some((authority_id, binding)) = live else {
            bail!("no complete selected Coding Agent Manager Claude account");
        };
        if frozen.authority_id.as_deref() != Some(authority_id.as_str())
            || !frozen.matches_selected_binding(&binding)
        {
            bail!("Coding Agent Manager Claude selection changed after observation");
        }
    }

    let data_dir = project_dirs()
        .map(|dirs| dirs.data_dir().to_path_buf())
        .context("Coding Agent Manager data directory is unavailable")?;
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data_dir));
    acquire_from_registry(
        &registry,
        &data_dir,
        frozen,
        socket_path.is_some(),
        deadline_unix_millis,
    )
}

fn acquire_from_registry(
    registry: &StoredAccountRegistry,
    data_dir: &Path,
    frozen: Option<&FrozenClaudeSelectedBinding>,
    socket_bound: bool,
    deadline_unix_millis: u64,
) -> Result<ClaudeLaunchAuthority> {
    let current = registry
        .selected_binding(CLAUDE_CODE_PROVIDER_ID)
        .context("failed to read Coding Agent Manager Claude selection")?
        .context("no complete selected Coding Agent Manager Claude account")?;
    let (binding, authority_id) = if let Some(frozen) = frozen {
        if let Some(expected) = &frozen.authority_id {
            if authority_id_for(registry.metadata_path()) != *expected {
                bail!("Coding Agent Manager Claude execution authority does not match observation");
            }
        }
        if !frozen.matches_selected_binding(&current) {
            bail!("Coding Agent Manager Claude selection changed after observation");
        }
        (frozen.to_selected_binding(), frozen.authority_id.clone())
    } else {
        (current, None)
    };
    let selected_use_lease = registry
        .acquire_selected_use(&binding)
        .context("failed to acquire selected Coding Agent Manager Claude account")?;
    let account = registry
        .complete(CLAUDE_CODE_PROVIDER_ID, &binding.account_id)
        .context("selected Coding Agent Manager Claude account is not complete")?;
    if account.auth_kind != AuthKind::OAuth || account.material != StoredAccountMaterial::VendorHome
    {
        bail!("selected Coding Agent Manager Claude account is not managed OAuth vendor-home material");
    }
    if !safe_account_component(&binding.account_id) {
        bail!("selected Coding Agent Manager Claude account id is unsafe");
    }
    let managed_home = data_dir
        .join("accounts")
        .join(CLAUDE_CODE_PROVIDER_ID)
        .join(&binding.account_id);
    require_private_managed_home(data_dir, &managed_home)?;
    let credential_path = managed_home.join(".credentials.json");
    let mut credential_file = open_credential_file(&credential_path)?;
    let (oauth_grant, credential_identity, oauth_expires_at_unix_millis) =
        read_oauth_grant(&mut credential_file, deadline_unix_millis)?;
    let (child_config_home, child_oauth_grant) = create_child_oauth_home(deadline_unix_millis)?;
    Ok(ClaudeLaunchAuthority {
        registry: StoredAccountRegistry::new(registry.metadata_path()),
        binding,
        authority_id,
        socket_bound,
        _selected_use_lease: selected_use_lease,
        #[cfg(test)]
        managed_home,
        managed_data_root: data_dir.to_path_buf(),
        child_config_home,
        credential_path,
        credential_file,
        credential_identity,
        oauth_expires_at_unix_millis,
        oauth_grant: Some(oauth_grant),
        child_oauth_grant: Some(child_oauth_grant),
    })
}

fn create_child_oauth_home(deadline_unix_millis: u64) -> Result<(tempfile::TempDir, Secret)> {
    let home = tempfile::Builder::new()
        .prefix("maco-claude-child-config-")
        .tempdir()
        .context("failed to create the private Claude child config home")?;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))?;
    let mut random = [0u8; 32];
    OpenOptions::new()
        .read(true)
        .open("/dev/urandom")
        .context("failed to open the kernel random source for the Claude child grant")?
        .read_exact(&mut random)
        .context("failed to read the Claude child grant")?;
    let token = format!("maco-child-oauth-{}", sha256_hex(&random));
    random.fill(0);
    let expires_at = deadline_unix_millis
        .checked_add(60_000)
        .context("Claude child OAuth expiry overflowed")?;
    let mut encoded = serde_json::to_vec(&serde_json::json!({
        "claudeAiOauth": {
            "accessToken": token.as_str(),
            "refreshToken": "maco-child-refresh-disabled",
            "expiresAt": expires_at,
            "scopes": ["user:inference"]
        },
        "organizationUuid": "maco-child-isolated"
    }))?;
    let credential_path = home.path().join(".credentials.json");
    let mut credential = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&credential_path)
        .context("failed to create the Claude child credential file")?;
    let write_result = credential
        .write_all(&encoded)
        .and_then(|()| credential.sync_all());
    encoded.fill(0);
    write_result.context("failed to write the Claude child credential file")?;
    Ok((home, Secret::new(token.into_bytes())))
}

#[cfg(test)]
pub(crate) fn acquire_claude_launch_authority_from(
    registry: &StoredAccountRegistry,
    data_dir: &Path,
    frozen: Option<&FrozenClaudeSelectedBinding>,
    deadline_unix_millis: u64,
) -> Result<ClaudeLaunchAuthority> {
    acquire_from_registry(registry, data_dir, frozen, false, deadline_unix_millis)
}

fn safe_account_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains("..")
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn require_private_managed_home(data_dir: &Path, path: &Path) -> Result<()> {
    let relative = path
        .strip_prefix(data_dir)
        .context("managed Claude home is outside the Coding Agent Manager data directory")?;
    let canonical_data_dir = fs::canonicalize(data_dir)
        .context("failed to canonicalize the Coding Agent Manager data directory")?;
    let canonical_home = fs::canonicalize(path).with_context(|| {
        format!(
            "failed to canonicalize managed Claude home {}",
            path.display()
        )
    })?;
    if canonical_home != canonical_data_dir.join(relative) {
        bail!("managed Claude home traverses a symbolic-link alias");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect managed Claude home {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("managed Claude home is not a non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!("managed Claude home is not private to the launch owner");
        }
    }
    Ok(())
}

fn open_credential_file(path: &Path) -> Result<File> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    };
    #[cfg(not(unix))]
    let file = OpenOptions::new().read(true).open(path);
    let file = file.context("failed to open managed Claude credential source")?;
    let metadata = file
        .metadata()
        .context("failed to inspect managed Claude credential source")?;
    if !metadata.is_file() || metadata.len() > MAX_CLAUDE_CREDENTIAL_BYTES as u64 {
        bail!("managed Claude credential source is not a bounded regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!("managed Claude credential source is not private to the launch owner");
        }
    }
    Ok(file)
}

fn read_oauth_grant(
    file: &mut File,
    deadline_unix_millis: u64,
) -> Result<(Secret, CredentialIdentity, u64)> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = SensitiveBytes::default();
    file.take((MAX_CLAUDE_CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes.0)?;
    if bytes.len() > MAX_CLAUDE_CREDENTIAL_BYTES {
        bail!("managed Claude credential source exceeds the bounded size");
    }
    let digest = sha256_hex(&bytes);
    let value = serde_json::from_slice::<UniqueJson>(&bytes)
        .context("managed Claude credential source is not unique-key JSON")?;
    let extracted = (|| -> Result<(Vec<u8>, u64)> {
        let oauth = value
            .0
            .as_object()
            .and_then(|root| root.get("claudeAiOauth"))
            .and_then(Value::as_object)
            .context("managed Claude credential source has no OAuth object")?;
        let expires_at = oauth
            .get("expiresAt")
            .and_then(Value::as_u64)
            .context("managed Claude OAuth access expiry is unavailable")?;
        let token = oauth
            .get("accessToken")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && !value.contains(['\r', '\n', '\0']))
            .context("managed Claude OAuth access token is unavailable")?
            .as_bytes()
            .to_vec();
        Ok((token, expires_at))
    })();
    let (mut token, expires_at) = extracted?;
    let now = match now_unix_millis() {
        Ok(now) => now,
        Err(error) => {
            token.fill(0);
            return Err(error);
        }
    };
    if expires_at <= deadline_unix_millis || deadline_unix_millis <= now {
        token.fill(0);
        bail!("managed Claude OAuth access token does not cover the launch deadline");
    }
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            token.fill(0);
            return Err(error.into());
        }
    };
    let identity = credential_identity(&metadata, digest);
    Ok((Secret::new(token), identity, expires_at))
}

#[derive(Default)]
struct SensitiveBytes(Vec<u8>);

impl std::ops::Deref for SensitiveBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Deserialize)]
struct SensitiveString(String);

impl Drop for SensitiveString {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        bytes.fill(0);
    }
}

fn zero_json_string_values(value: &mut Value) {
    match value {
        Value::String(string) => {
            let mut bytes = std::mem::take(string).into_bytes();
            bytes.fill(0);
        }
        Value::Array(values) => values.iter_mut().for_each(zero_json_string_values),
        Value::Object(values) => {
            for (key, mut value) in std::mem::take(values) {
                let mut key = key.into_bytes();
                key.fill(0);
                zero_json_string_values(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn verify_credential_source(
    held: &mut File,
    path: &Path,
    expected: &CredentialIdentity,
) -> Result<()> {
    let observed = open_credential_file(path)?;
    if credential_identity(&observed.metadata()?, String::new())
        != credential_identity_without_digest(expected)
    {
        bail!("managed Claude credential source identity changed");
    }
    held.seek(SeekFrom::Start(0))?;
    let mut bytes = SensitiveBytes::default();
    held.take((MAX_CLAUDE_CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes.0)?;
    let unchanged =
        bytes.len() <= MAX_CLAUDE_CREDENTIAL_BYTES && sha256_hex(&bytes) == expected.digest;
    if !unchanged {
        bail!("managed Claude credential source changed");
    }
    Ok(())
}

fn credential_identity(metadata: &fs::Metadata, digest: String) -> CredentialIdentity {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    CredentialIdentity {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        length: metadata.len(),
        modified: metadata.modified().ok(),
        digest,
    }
}

fn credential_identity_without_digest(identity: &CredentialIdentity) -> CredentialIdentity {
    CredentialIdentity {
        #[cfg(unix)]
        device: identity.device,
        #[cfg(unix)]
        inode: identity.inode,
        length: identity.length,
        modified: identity.modified,
        digest: String::new(),
    }
}

fn now_unix_millis() -> Result<u64> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("current time does not fit Claude deadline representation")
}

struct UniqueJson(Value);

impl Drop for UniqueJson {
    fn drop(&mut self) {
        zero_json_string_values(&mut self.0);
    }
}

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Value;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_map<A>(self, mut access: A) -> std::result::Result<Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut guarded = UniqueJson(Value::Object(Map::new()));
                while let Some(mut key) = access.next_key::<SensitiveString>()? {
                    let mut value = access.next_value::<UniqueJson>()?;
                    let map = guarded.0.as_object_mut().expect("map guard");
                    if map.contains_key(key.0.as_str()) {
                        return Err(A::Error::custom("duplicate JSON object key"));
                    }
                    let key = std::mem::take(&mut key.0);
                    let value = std::mem::replace(&mut value.0, Value::Null);
                    map.insert(key, value);
                }
                Ok(std::mem::replace(&mut guarded.0, Value::Null))
            }
            fn visit_seq<A>(self, mut access: A) -> std::result::Result<Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut guarded = UniqueJson(Value::Array(Vec::new()));
                while let Some(mut value) = access.next_element::<UniqueJson>()? {
                    let value = std::mem::replace(&mut value.0, Value::Null);
                    guarded.0.as_array_mut().expect("array guard").push(value);
                }
                Ok(std::mem::replace(&mut guarded.0, Value::Null))
            }
            fn visit_bool<E>(self, value: bool) -> std::result::Result<Value, E> {
                Ok(Value::Bool(value))
            }
            fn visit_i64<E>(self, value: i64) -> std::result::Result<Value, E> {
                Ok(Value::from(value))
            }
            fn visit_u64<E>(self, value: u64) -> std::result::Result<Value, E> {
                Ok(Value::from(value))
            }
            fn visit_f64<E>(self, value: f64) -> std::result::Result<Value, E> {
                Ok(Value::from(value))
            }
            fn visit_str<E>(self, value: &str) -> std::result::Result<Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Value::String(value.to_owned()))
            }
            fn visit_string<E>(self, value: String) -> std::result::Result<Value, E> {
                Ok(Value::String(value))
            }
            fn visit_none<E>(self) -> std::result::Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_unit<E>(self) -> std::result::Result<Value, E> {
                Ok(Value::Null)
            }
        }
        deserializer.deserialize_any(UniqueVisitor).map(UniqueJson)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};
    use std::fs;

    fn fixture_credentials(token: &str, expires_at: u64) -> String {
        format!(
            "{{\"claudeAiOauth\":{{\"accessToken\":\"{token}\",\"refreshToken\":\"fake-refresh\",\"expiresAt\":{expires_at}}},\"organizationUuid\":\"fake-org\"}}"
        )
    }

    fn selected_fixture() -> Result<(tempfile::TempDir, StoredAccountRegistry, PathBuf, u64)> {
        let root = tempfile::tempdir()?;
        let data = root.path().join("data");
        fs::create_dir_all(&data)?;
        let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
        registry.begin_add(
            CLAUDE_CODE_PROVIDER_ID,
            "work",
            "Work",
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )?;
        registry.complete_add(CLAUDE_CODE_PROVIDER_ID, "work")?;
        registry.select_complete_revision(CLAUDE_CODE_PROVIDER_ID, "work", None)?;
        let home = data
            .join("accounts")
            .join(CLAUDE_CODE_PROVIDER_ID)
            .join("work");
        fs::create_dir_all(&home)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        }
        let deadline = now_unix_millis()?.saturating_add(60_000);
        let credentials = home.join(".credentials.json");
        fs::write(
            &credentials,
            fixture_credentials("fake-oauth-access-token", deadline.saturating_add(60_000)),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&credentials, fs::Permissions::from_mode(0o600))?;
        }
        Ok((root, registry, data, deadline))
    }

    #[test]
    fn selected_managed_oauth_grant_is_bound_and_revalidated() -> Result<()> {
        let (_root, registry, data, deadline) = selected_fixture()?;
        let binding = registry
            .selected_binding(CLAUDE_CODE_PROVIDER_ID)?
            .context("selected binding")?;
        let frozen = FrozenClaudeSelectedBinding::from_selected_binding(
            Some(authority_id_for(registry.metadata_path())),
            &binding,
        );
        let mut authority =
            acquire_claude_launch_authority_from(&registry, &data, Some(&frozen), deadline)?;
        assert_eq!(authority.oauth_grant_bytes()?, b"fake-oauth-access-token");
        let mut environment = BTreeMap::from([
            ("ANTHROPIC_API_KEY".to_string(), "ambient".to_string()),
            ("ANTHROPIC_AUTH_TOKEN".to_string(), "ambient".to_string()),
            ("CLAUDE_CODE_OAUTH_TOKEN".to_string(), "ambient".to_string()),
            (
                "CLAUDE_SECURESTORAGE_CONFIG_DIR".to_string(),
                "/ambient".to_string(),
            ),
        ]);
        authority.apply_launch_environment(&mut environment);
        assert!(!environment.contains_key("ANTHROPIC_API_KEY"));
        assert!(!environment.contains_key("ANTHROPIC_AUTH_TOKEN"));
        assert!(!environment.contains_key("CLAUDE_CODE_OAUTH_TOKEN"));
        assert!(!environment.contains_key("CLAUDE_SECURESTORAGE_CONFIG_DIR"));
        assert_eq!(
            environment.get("CLAUDE_CONFIG_DIR").map(String::as_str),
            authority.child_config_home().to_str()
        );
        assert_ne!(authority.child_config_home(), authority.managed_home());
        assert_ne!(authority.child_config_home(), authority.managed_data_root());
        let child_credential_path = authority.child_config_home().join(".credentials.json");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(authority.child_config_home())?
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&child_credential_path)?.permissions().mode() & 0o777,
                0o600
            );
        }
        let child_credentials = fs::read(child_credential_path)?;
        assert!(!child_credentials
            .windows(b"fake-oauth-access-token".len())
            .any(|window| window == b"fake-oauth-access-token"));
        let child_grant = authority.take_child_oauth_grant()?;
        assert!(child_credentials
            .windows(child_grant.expose().len())
            .any(|window| window == child_grant.expose()));
        let child_json: Value = serde_json::from_slice(&child_credentials)?;
        assert_eq!(
            child_json["claudeAiOauth"]["scopes"],
            serde_json::json!(["user:inference"])
        );
        authority.verify_binding_unchanged()?;
        authority.oauth_expires_at_unix_millis = now_unix_millis()?.saturating_sub(1);
        assert!(authority.verify_binding_unchanged().is_err());
        authority.oauth_expires_at_unix_millis = deadline.saturating_add(60_000);
        fs::write(
            authority.managed_home().join(".credentials.json"),
            fixture_credentials(
                "changed-oauth-access-token",
                deadline.saturating_add(60_000),
            ),
        )?;
        assert!(authority.verify_binding_unchanged().is_err());
        Ok(())
    }

    #[test]
    fn duplicate_oauth_keys_and_deadline_shortfall_are_refused() -> Result<()> {
        let (_root, registry, data, deadline) = selected_fixture()?;
        let home = data
            .join("accounts")
            .join(CLAUDE_CODE_PROVIDER_ID)
            .join("work");
        let path = home.join(".credentials.json");
        fs::write(
            &path,
            format!(
                "{{\"claudeAiOauth\":{{\"accessToken\":\"first-fake-token\",\"accessToken\":\"second-fake-token\",\"expiresAt\":{}}}}}",
                deadline.saturating_add(60_000)
            ),
        )?;
        let duplicate_error =
            acquire_claude_launch_authority_from(&registry, &data, None, deadline)
                .err()
                .expect("duplicate OAuth keys must fail");
        let duplicate_error = format!("{duplicate_error:#}");
        assert!(!duplicate_error.contains("first-fake-token"));
        assert!(!duplicate_error.contains("second-fake-token"));
        fs::write(
            &path,
            r#"{"claudeAiOauth":{"accessToken":"must-not-be-copied-before-expiry-validation","expiresAt":"invalid"}}"#,
        )?;
        let malformed_error =
            acquire_claude_launch_authority_from(&registry, &data, None, deadline)
                .err()
                .expect("malformed OAuth metadata must fail");
        assert!(
            !format!("{malformed_error:#}").contains("must-not-be-copied-before-expiry-validation")
        );
        fs::write(
            &path,
            fixture_credentials("fake-oauth-access-token", deadline),
        )?;
        assert!(acquire_claude_launch_authority_from(&registry, &data, None, deadline).is_err());
        Ok(())
    }
}
