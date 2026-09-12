use super::{
    evaluation::{self, PreviewInput},
    protocol::{valid_alias, MAX_FRAME_BYTES, MAX_REQUEST_SECONDS},
    AccountClient, AccountClientConfig, AccountError,
};
use crate::safe_state::BoundedRegularReader;
use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Serialize;
use std::{path::PathBuf, time::Duration};

#[derive(Debug, Args)]
pub(crate) struct AccountsCommand {
    /// Explicit trusted capability-service Unix socket. Linux only.
    #[arg(long)]
    broker_socket: PathBuf,
    /// Expected service UID; checked against directory, socket and SO_PEERCRED.
    #[arg(long)]
    broker_uid: u32,
    /// Complete request deadline, at most the service's 60-second contract.
    #[arg(long, default_value_t = MAX_REQUEST_SECONDS, value_parser = clap::value_parser!(u64).range(1..=MAX_REQUEST_SECONDS))]
    timeout_seconds: u64,
    #[command(subcommand)]
    command: AccountsSubcommand,
}

#[derive(Debug, Subcommand)]
enum AccountsSubcommand {
    /// List registered aliases without querying a provider.
    List,
    /// Observe metadata only for this exact manually selected alias.
    Discover { alias: String },
    /// Evaluate complete-policy evidence for one alias; never authorizes execution.
    Preview {
        alias: String,
        /// Bounded JSON policy evidence with the same exact account pin.
        #[arg(long)]
        policies: PathBuf,
    },
}

#[derive(Serialize)]
struct ErrorReport {
    schema_version: u32,
    error: AccountError,
}

impl AccountsCommand {
    pub(crate) fn run(self) -> Result<()> {
        let result = self.execute();
        match result {
            Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
            Err(error) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ErrorReport {
                        schema_version: 1,
                        error
                    })?
                );
                return Err(error.into());
            }
        }
        Ok(())
    }

    fn execute(self) -> Result<serde_json::Value, AccountError> {
        let client = AccountClient::new(AccountClientConfig {
            socket: self.broker_socket,
            expected_uid: self.broker_uid,
            timeout: Duration::from_secs(self.timeout_seconds),
        })?;
        match self.command {
            AccountsSubcommand::List => {
                serde_json::to_value(client.list()?).map_err(|_| AccountError::Protocol)
            }
            AccountsSubcommand::Discover { alias } => {
                serde_json::to_value(client.discover(&alias)?).map_err(|_| AccountError::Protocol)
            }
            AccountsSubcommand::Preview { alias, policies } => {
                if !valid_alias(&alias) {
                    return Err(AccountError::InvalidInput);
                }
                // The preview input shares the capability protocol frame bound.
                let bytes =
                    BoundedRegularReader::read_tree_no_follow(policies, MAX_FRAME_BYTES as u64)
                        .map_err(|_| AccountError::InvalidInput)?;
                let input: PreviewInput =
                    serde_json::from_slice(&bytes).map_err(|_| AccountError::InvalidInput)?;
                if input.account_alias != alias {
                    return Err(AccountError::InvalidInput);
                }
                serde_json::to_value(evaluation::preview(&client, &input)?)
                    .map_err(|_| AccountError::Protocol)
            }
        }
    }
}
