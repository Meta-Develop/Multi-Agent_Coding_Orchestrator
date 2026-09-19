//! Coding Agent Manager — application core.
//!
//! Layering (enforced by review, see `docs/ARCHITECTURE.md`):
//!
//! ```text
//! commands  ->  providers | storage | relay | router
//! providers ->  storage | backup | fsx
//! relay     ->  router -> providers
//! backup    ->  fsx | paths
//! storage   ->  paths
//! ```
//!
//! Nothing below `commands` may depend on Tauri types, so the core stays
//! testable without a webview and reusable from a future headless binary.

pub mod account_authority;
pub mod backup;
pub mod error;
pub mod fsx;
pub mod login;
pub mod model;
pub mod paths;
pub mod providers;
pub mod relay;
pub mod router;
pub mod storage;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_exposes_the_registered_providers() {
        let ids: Vec<_> = providers::registry()
            .iter()
            .map(|adapter| adapter.id())
            .collect();
        assert_eq!(
            ids,
            vec![
                "claude-code",
                "codex-cli",
                "cursor",
                "grok-cli",
                "gemini-cli",
                "github-copilot",
            ]
        );
    }

    #[test]
    fn every_adapter_id_is_unique() {
        let mut ids: Vec<_> = providers::registry()
            .iter()
            .map(|adapter| adapter.id())
            .collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate provider id in registry()");
    }

    #[test]
    fn find_resolves_a_known_id_and_rejects_an_unknown_one() {
        assert!(providers::find("codex-cli").is_some());
        assert!(providers::find("not-a-provider").is_none());
    }

    #[test]
    fn descriptors_never_claim_more_maturity_than_implemented() {
        // Until an adapter implements list_accounts, it must not advertise
        // itself as `supported`. This test is the guard that keeps the UI
        // honest as adapters land one at a time.
        for adapter in providers::registry() {
            let descriptor = adapter.descriptor();
            if matches!(descriptor.maturity, model::Maturity::Supported) {
                assert!(
                    adapter.list_accounts().is_ok(),
                    "`{}` claims `supported` but cannot list accounts",
                    descriptor.id
                );
            }
        }
    }
}
