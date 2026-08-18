use super::SshTargetConfig;
use serde::{Deserialize, Deserializer, Serialize};

/// Operator-selected executor configuration.
///
/// This DTO selects an execution boundary only. It does not construct an SSH
/// transport, start a process, or convert remote candidate evidence into a local
/// [`crate::external_agent::ExternalAgentRun`]. The local variant remains the
/// default; SSH must be selected explicitly with a credential-free typed target.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutorSelection {
    #[default]
    Local,
    Ssh {
        target: SshTargetConfig,
    },
}

impl<'de> Deserialize<'de> for ExecutorSelection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum StrictSelection {
            Local {},
            Ssh { target: SshTargetConfig },
        }

        match StrictSelection::deserialize(deserializer)? {
            StrictSelection::Local {} => Ok(Self::Local),
            StrictSelection::Ssh { target } => Ok(Self::Ssh { target }),
        }
    }
}

impl ExecutorSelection {
    pub fn local() -> Self {
        Self::Local
    }

    pub fn ssh(target: SshTargetConfig) -> Self {
        Self::Ssh { target }
    }

    pub fn ssh_target(&self) -> Option<&SshTargetConfig> {
        match self {
            Self::Local => None,
            Self::Ssh { target } => Some(target),
        }
    }
}
