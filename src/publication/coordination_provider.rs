//! Read-only parent provider observation for bound publication effects (#410).

use super::coordination_effect::{
    github_pull_request_external_effect_payload_digest, unmarked_pr_body_from_marked_body,
    validate_external_effect_marker_for_descriptor, GitPushParentObservationV1,
    GitPushPublicationEffectFieldsV1, GithubPullRequestParentObservationInput,
    GithubPullRequestParentObservationV1, GithubPullRequestPublicationEffectFieldsV1,
    ParentObservedPublicationMaterialV1, ParentObservedPublicationObservationV1,
    PublicationEffectDescriptorV1, PublicationEffectLiveVerification,
    PublicationEffectLiveVerifier, PublicationEffectOperationV1,
};
use super::{CliGithubApi, GithubApi, GithubPrResult, GithubRepositoryIdentity};
use anyhow::Result;
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::sync::Arc;

#[derive(Debug)]
pub(crate) enum BoundObservationFailure {
    Refused(anyhow::Error),
    Unknown(anyhow::Error),
}

impl BoundObservationFailure {
    fn refused(message: impl Into<String>) -> Self {
        Self::Refused(anyhow::anyhow!(message.into()))
    }

    fn unknown(error: anyhow::Error) -> Self {
        Self::Unknown(error)
    }
}

pub(crate) trait BoundPublicationProviderObserver: Send + Sync {
    fn observe_git_push_head_oid(
        &self,
        worktree: &Path,
        remote_url: &str,
        lookup_ref: &str,
    ) -> Result<Option<String>, BoundObservationFailure>;

    fn observe_git_push_base_oid(
        &self,
        worktree: &Path,
        remote_url: &str,
        base_ref: &str,
    ) -> Result<Option<String>, BoundObservationFailure>;

    fn list_github_pull_requests(
        &self,
        worktree: &Path,
        head_branch: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<Vec<GithubPrResult>, BoundObservationFailure>;

    fn view_github_pull_request(
        &self,
        worktree: &Path,
        selector: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<GithubPrResult, BoundObservationFailure>;
}

struct ProductionBoundPublicationObserver;

impl BoundPublicationProviderObserver for ProductionBoundPublicationObserver {
    fn observe_git_push_head_oid(
        &self,
        worktree: &Path,
        remote_url: &str,
        lookup_ref: &str,
    ) -> Result<Option<String>, BoundObservationFailure> {
        super::observe_remote_ref(worktree, remote_url, lookup_ref)
            .map_err(BoundObservationFailure::unknown)
    }

    fn observe_git_push_base_oid(
        &self,
        worktree: &Path,
        remote_url: &str,
        base_ref: &str,
    ) -> Result<Option<String>, BoundObservationFailure> {
        super::observe_remote_ref(worktree, remote_url, base_ref)
            .map_err(BoundObservationFailure::unknown)
    }

    fn list_github_pull_requests(
        &self,
        worktree: &Path,
        head_branch: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<Vec<GithubPrResult>, BoundObservationFailure> {
        let mut api = CliGithubApi;
        api.list(worktree, head_branch, repository)
            .map_err(BoundObservationFailure::unknown)
    }

    fn view_github_pull_request(
        &self,
        worktree: &Path,
        selector: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<GithubPrResult, BoundObservationFailure> {
        let mut api = CliGithubApi;
        api.view(worktree, selector, repository)
            .map_err(BoundObservationFailure::unknown)
    }
}

enum ObserverBackend {
    Production,
    #[cfg(test)]
    Injected(Arc<dyn BoundPublicationProviderObserver>),
}

pub(crate) struct ParentPublicationProviderVerifier {
    worktree: PathBuf,
    observer: ObserverBackend,
}

impl ParentPublicationProviderVerifier {
    pub(crate) fn new(worktree: PathBuf) -> Self {
        Self {
            worktree,
            observer: ObserverBackend::Production,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_injected_observer(
        worktree: PathBuf,
        observer: Arc<dyn BoundPublicationProviderObserver>,
    ) -> Self {
        Self {
            worktree,
            observer: ObserverBackend::Injected(observer),
        }
    }

    fn observer(&self) -> &dyn BoundPublicationProviderObserver {
        match &self.observer {
            ObserverBackend::Production => &ProductionBoundPublicationObserver,
            #[cfg(test)]
            ObserverBackend::Injected(observer) => observer.as_ref(),
        }
    }

    pub(crate) fn observe_bound_completion(
        &self,
        descriptor: &PublicationEffectDescriptorV1,
        reserve_event_nonce: &str,
    ) -> Result<ParentObservedPublicationMaterialV1> {
        match self.observe_bound_completion_inner(descriptor, reserve_event_nonce) {
            Ok(material) => Ok(material),
            Err(BoundObservationFailure::Refused(error)) => Err(error),
            Err(BoundObservationFailure::Unknown(error)) => Err(error),
        }
    }

    fn observe_bound_completion_inner(
        &self,
        descriptor: &PublicationEffectDescriptorV1,
        reserve_event_nonce: &str,
    ) -> Result<ParentObservedPublicationMaterialV1, BoundObservationFailure> {
        descriptor.validate().map_err(|error| {
            BoundObservationFailure::refused(format!(
                "bound publication descriptor was invalid: {error:#}"
            ))
        })?;
        let observation = match descriptor.operation() {
            PublicationEffectOperationV1::GitPush(fields) => {
                ParentObservedPublicationObservationV1::GitPush(
                    self.observe_git_push(descriptor, fields)?,
                )
            }
            PublicationEffectOperationV1::GithubPullRequest(fields) => {
                ParentObservedPublicationObservationV1::GithubPullRequest(
                    self.observe_github_pull_request(descriptor, fields)?,
                )
            }
        };
        ParentObservedPublicationMaterialV1::try_new(
            reserve_event_nonce,
            descriptor.clone(),
            observation,
        )
        .map_err(|error| {
            BoundObservationFailure::refused(format!(
                "bound publication material was not canonical: {error:#}"
            ))
        })
    }

    fn observe_git_push(
        &self,
        descriptor: &PublicationEffectDescriptorV1,
        fields: &GitPushPublicationEffectFieldsV1,
    ) -> Result<GitPushParentObservationV1, BoundObservationFailure> {
        if descriptor.transport_provider() != "git" {
            return Err(BoundObservationFailure::refused(
                "git push descriptor used a non-git transport provider",
            ));
        }
        let remote_url = fields.network_locator().observation_remote_url();
        let base_ref = format!("refs/heads/{}", fields.base_branch());
        let base_observed =
            self.observer()
                .observe_git_push_base_oid(&self.worktree, remote_url, &base_ref)?;
        if base_observed.as_deref() != Some(fields.expected_base_oid()) {
            return Err(BoundObservationFailure::refused(
                "git push base ref observation did not match descriptor expected base oid",
            ));
        }
        let head_observed = self.observer().observe_git_push_head_oid(
            &self.worktree,
            remote_url,
            fields.lookup_ref(),
        )?;
        let observed_head = head_observed.ok_or_else(|| {
            BoundObservationFailure::refused("git push lookup ref was absent on the network remote")
        })?;
        if observed_head != fields.expected_head_oid() {
            return Err(BoundObservationFailure::refused(
                "git push head ref observation did not match descriptor expected head oid",
            ));
        }
        GitPushParentObservationV1::try_new(fields.lookup_ref(), observed_head).map_err(|error| {
            BoundObservationFailure::refused(format!(
                "git push observation was malformed: {error:#}"
            ))
        })
    }

    fn observe_github_pull_request(
        &self,
        descriptor: &PublicationEffectDescriptorV1,
        fields: &GithubPullRequestPublicationEffectFieldsV1,
    ) -> Result<GithubPullRequestParentObservationV1, BoundObservationFailure> {
        if descriptor.transport_provider() != "github" {
            return Err(BoundObservationFailure::refused(
                "github pull request descriptor used a non-github transport provider",
            ));
        }
        validate_external_effect_marker_for_descriptor(descriptor, fields.marker()).map_err(
            |error| {
                BoundObservationFailure::refused(format!(
                    "github pull request marker was invalid: {error:#}"
                ))
            },
        )?;
        let repository = github_repository_for_descriptor(descriptor, fields)?;
        let candidates = self.observer().list_github_pull_requests(
            &self.worktree,
            fields.lookup_head_branch(),
            &repository,
        )?;
        let mut exact = Vec::new();
        for candidate in candidates {
            if !pr_list_candidate_matches_descriptor(fields, &candidate) {
                continue;
            }
            let viewed = self.observer().view_github_pull_request(
                &self.worktree,
                &candidate.number.to_string(),
                &repository,
            )?;
            if !pr_view_matches_descriptor(fields, &viewed)? {
                continue;
            }
            super::validate_github_receipt_url(&viewed.url, &repository, viewed.number).map_err(
                |error| {
                    BoundObservationFailure::refused(format!(
                        "github pull request receipt url was invalid: {error:#}"
                    ))
                },
            )?;
            exact.push(viewed);
        }
        exact.sort_by_key(|receipt| receipt.number);
        if exact.len() != 1 {
            return Err(BoundObservationFailure::refused(format!(
                "github pull request lookup found {} exact candidates, expected 1",
                exact.len()
            )));
        }
        let viewed = exact[0].clone();
        let payload_digest = github_pull_request_external_effect_payload_digest(
            &viewed.title,
            &unmarked_pr_body_from_marked_body(&viewed.body, fields.marker()).map_err(|error| {
                BoundObservationFailure::refused(format!(
                    "github pull request payload could not be reconstructed: {error:#}"
                ))
            })?,
            viewed.is_draft,
            fields.expected_author(),
        )
        .map_err(|error| {
            BoundObservationFailure::refused(format!(
                "github pull request payload digest failed: {error:#}"
            ))
        })?;
        if payload_digest != descriptor.payload_digest() {
            return Err(BoundObservationFailure::refused(
                "github pull request payload digest did not match descriptor",
            ));
        }
        GithubPullRequestParentObservationV1::try_new(GithubPullRequestParentObservationInput {
            number: viewed.number,
            url: viewed.url,
            head_oid: viewed.head_oid,
            base_oid: viewed.base_oid,
            base_ref_name: viewed.base_ref_name,
            head_ref_name: viewed.head_ref_name,
            author: viewed.author,
            is_draft: viewed.is_draft,
            state: viewed.state,
        })
        .map_err(|error| {
            BoundObservationFailure::refused(format!(
                "github pull request observation was malformed: {error:#}"
            ))
        })
    }
}

impl PublicationEffectLiveVerifier for ParentPublicationProviderVerifier {
    fn verify_live_bound_completion(
        &self,
        _owner: &super::coordination_journal::CoordinationOwnerIdentity,
        descriptor: &PublicationEffectDescriptorV1,
        material: &ParentObservedPublicationMaterialV1,
    ) -> PublicationEffectLiveVerification {
        match self.observe_bound_completion_inner(descriptor, material.reserve_event_nonce()) {
            Ok(observed) if observed == *material => PublicationEffectLiveVerification::Verified,
            Ok(_) => PublicationEffectLiveVerification::Refused,
            Err(BoundObservationFailure::Refused(_)) => PublicationEffectLiveVerification::Refused,
            Err(BoundObservationFailure::Unknown(_)) => PublicationEffectLiveVerification::Unknown,
        }
    }
}

fn github_repository_for_descriptor(
    descriptor: &PublicationEffectDescriptorV1,
    fields: &GithubPullRequestPublicationEffectFieldsV1,
) -> Result<GithubRepositoryIdentity, BoundObservationFailure> {
    let repository = super::github_repository_identity_from_selector(
        descriptor.repository_selector(),
    )
    .map_err(|error| {
        BoundObservationFailure::refused(format!(
            "descriptor repository selector was invalid: {error:#}"
        ))
    })?;
    if repository.owner != fields.repository_owner() || repository.name != fields.repository_name()
    {
        return Err(BoundObservationFailure::refused(
            "descriptor repository identity did not match github pull request fields",
        ));
    }
    Ok(repository)
}

fn pr_list_candidate_matches_descriptor(
    fields: &GithubPullRequestPublicationEffectFieldsV1,
    receipt: &GithubPrResult,
) -> bool {
    receipt.head_oid == fields.expected_head_oid()
        && receipt.base_oid == fields.expected_base_oid()
        && receipt.base_ref_name == fields.base_branch()
        && receipt.head_ref_name == fields.lookup_head_branch()
        && receipt.author == fields.expected_author()
        && receipt.is_draft == fields.draft()
        && receipt.state == "OPEN"
        && receipt.head_repository_owner == fields.repository_owner()
        && receipt.head_repository_name == fields.repository_name()
        && !receipt.is_cross_repository
}

fn pr_view_matches_descriptor(
    fields: &GithubPullRequestPublicationEffectFieldsV1,
    viewed: &GithubPrResult,
) -> Result<bool, BoundObservationFailure> {
    if !pr_list_candidate_matches_descriptor(fields, viewed) {
        return Ok(false);
    }
    if !viewed.body.contains(fields.marker()) {
        return Ok(false);
    }
    if viewed.body.matches(fields.marker()).count() != 1 {
        return Err(BoundObservationFailure::refused(
            "github pull request body did not contain exactly one effect marker",
        ));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::super::coordination_effect::GithubPullRequestPublicationEffectIdentity;
    use super::*;
    use crate::publication::coordination_effect::{
        expected_publication_effect_id_without_source_parts,
        git_push_external_effect_payload_digest, git_push_external_effect_target_digest,
        git_push_remote_binding_digest, github_pull_request_external_effect_target_digest,
        PublicationEffectDescriptorBinding, PublicationEffectOperationV1,
        PublicationGitNetworkLocatorV1,
    };
    use std::sync::{Arc, Mutex};

    struct ScriptedObserver {
        head_oid: Mutex<Option<String>>,
        base_oid: Mutex<Option<String>>,
        list: Mutex<Vec<GithubPrResult>>,
        view: Mutex<Option<GithubPrResult>>,
        calls: Mutex<Vec<&'static str>>,
    }

    impl ScriptedObserver {
        fn new() -> Self {
            Self {
                head_oid: Mutex::new(None),
                base_oid: Mutex::new(None),
                list: Mutex::new(Vec::new()),
                view: Mutex::new(None),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn record(&self, label: &'static str) {
            self.calls.lock().expect("lock").push(label);
        }
    }

    impl BoundPublicationProviderObserver for ScriptedObserver {
        fn observe_git_push_head_oid(
            &self,
            _worktree: &Path,
            _remote_url: &str,
            _lookup_ref: &str,
        ) -> Result<Option<String>, BoundObservationFailure> {
            self.record("git_head");
            Ok(self.head_oid.lock().expect("lock").clone())
        }

        fn observe_git_push_base_oid(
            &self,
            _worktree: &Path,
            _remote_url: &str,
            _base_ref: &str,
        ) -> Result<Option<String>, BoundObservationFailure> {
            self.record("git_base");
            Ok(self.base_oid.lock().expect("lock").clone())
        }

        fn list_github_pull_requests(
            &self,
            _worktree: &Path,
            _head_branch: &str,
            _repository: &GithubRepositoryIdentity,
        ) -> Result<Vec<GithubPrResult>, BoundObservationFailure> {
            self.record("gh_list");
            Ok(self.list.lock().expect("lock").clone())
        }

        fn view_github_pull_request(
            &self,
            _worktree: &Path,
            _selector: &str,
            _repository: &GithubRepositoryIdentity,
        ) -> Result<GithubPrResult, BoundObservationFailure> {
            self.record("gh_view");
            self.view
                .lock()
                .expect("lock")
                .clone()
                .ok_or_else(|| BoundObservationFailure::refused("missing view"))
        }
    }

    fn sample_git_descriptor() -> PublicationEffectDescriptorV1 {
        let locator = PublicationGitNetworkLocatorV1::try_new("https://github.com/acme/repo.git")
            .expect("locator");
        let fields = GitPushPublicationEffectFieldsV1::new(
            "origin",
            locator.clone(),
            "refs/heads/maco/effects/abcd",
            "main",
            "c".repeat(40),
            "d".repeat(40),
            git_push_remote_binding_digest("origin", &locator).expect("binding"),
        )
        .expect("fields");
        let target_digest = git_push_external_effect_target_digest(
            "github.com/acme/repo",
            fields.remote_name(),
            fields.network_locator(),
            fields.base_branch(),
            fields.expected_base_oid(),
        )
        .expect("target");
        let payload_digest =
            git_push_external_effect_payload_digest(fields.expected_head_oid()).expect("payload");
        let operation = PublicationEffectOperationV1::GitPush(fields.clone());
        let effect_id = expected_publication_effect_id_without_source_parts(
            "git",
            "github.com/acme/repo",
            "repo-binding",
            &operation,
            &target_digest,
            &payload_digest,
        )
        .expect("effect id");
        PublicationEffectDescriptorV1::try_new_git_push(
            PublicationEffectDescriptorBinding {
                effect_id,
                transport_provider: "git".to_string(),
                repository_selector: "github.com/acme/repo".to_string(),
                repository_identity: "repo-binding".to_string(),
                source_provenance_digest: None,
                target_digest,
                payload_digest,
            },
            fields,
        )
        .expect("descriptor")
    }

    fn sample_pr_descriptor(title: &str, body: &str) -> PublicationEffectDescriptorV1 {
        let target_digest = github_pull_request_external_effect_target_digest(
            "github.com/acme/repo",
            &"d".repeat(40),
            &"c".repeat(40),
            "main",
        )
        .expect("target");
        let payload_digest =
            github_pull_request_external_effect_payload_digest(title, body, false, "bot")
                .expect("payload");
        let stub_marker = format!("<!-- maco-external-effect:v2:{} -->", "a".repeat(64));
        let stub_fields = GithubPullRequestPublicationEffectFieldsV1::new(
            GithubPullRequestPublicationEffectIdentity {
                repository_owner: "acme".to_string(),
                repository_name: "repo".to_string(),
                lookup_head_branch: "maco/effects/abcd".to_string(),
                base_branch: "main".to_string(),
                expected_base_oid: "c".repeat(40),
                expected_head_oid: "d".repeat(40),
                draft: false,
                expected_author: "bot".to_string(),
                marker: stub_marker,
            },
        )
        .expect("stub fields");
        let effect_id = expected_publication_effect_id_without_source_parts(
            "github",
            "github.com/acme/repo",
            "repo-binding",
            &PublicationEffectOperationV1::GithubPullRequest(stub_fields),
            &target_digest,
            &payload_digest,
        )
        .expect("effect id");
        let marker = format!("<!-- maco-external-effect:v2:{effect_id} -->");
        let fields = GithubPullRequestPublicationEffectFieldsV1::new(
            GithubPullRequestPublicationEffectIdentity {
                repository_owner: "acme".to_string(),
                repository_name: "repo".to_string(),
                lookup_head_branch: "maco/effects/abcd".to_string(),
                base_branch: "main".to_string(),
                expected_base_oid: "c".repeat(40),
                expected_head_oid: "d".repeat(40),
                draft: false,
                expected_author: "bot".to_string(),
                marker,
            },
        )
        .expect("fields");
        PublicationEffectDescriptorV1::try_new_github_pull_request(
            PublicationEffectDescriptorBinding {
                effect_id,
                transport_provider: "github".to_string(),
                repository_selector: "github.com/acme/repo".to_string(),
                repository_identity: "repo-binding".to_string(),
                source_provenance_digest: None,
                target_digest,
                payload_digest,
            },
            fields,
        )
        .expect("descriptor")
    }

    #[test]
    fn fresh_host_git_push_observation_uses_https_locator_without_local_wal() {
        let observer = Arc::new(ScriptedObserver::new());
        *observer.base_oid.lock().expect("lock") = Some("c".repeat(40));
        *observer.head_oid.lock().expect("lock") = Some("d".repeat(40));
        let verifier = ParentPublicationProviderVerifier::with_injected_observer(
            PathBuf::from("/tmp/fresh-host"),
            observer.clone(),
        );
        let descriptor = sample_git_descriptor();
        let material = verifier
            .observe_bound_completion(&descriptor, "evt-reserve")
            .expect("material");
        assert_eq!(material.reserve_event_nonce(), "evt-reserve");
        let calls = observer.calls.lock().expect("lock");
        assert!(calls.contains(&"git_head"));
        assert!(calls.contains(&"git_base"));
        assert!(!calls.contains(&"gh_list"));
    }

    #[test]
    fn changed_git_head_refuses_live_verification() {
        let observer = Arc::new(ScriptedObserver::new());
        *observer.base_oid.lock().expect("lock") = Some("c".repeat(40));
        *observer.head_oid.lock().expect("lock") = Some("e".repeat(40));
        let verifier = ParentPublicationProviderVerifier::with_injected_observer(
            PathBuf::from("/tmp/fresh-host"),
            observer,
        );
        let descriptor = sample_git_descriptor();
        assert!(verifier
            .observe_bound_completion(&descriptor, "evt")
            .is_err());
    }

    #[test]
    fn github_pull_request_observation_rebuilds_payload_digest_from_view() {
        let descriptor = sample_pr_descriptor("title", "body");
        let marker = match descriptor.operation() {
            PublicationEffectOperationV1::GithubPullRequest(fields) => fields.marker().to_string(),
            _ => panic!("pr descriptor"),
        };
        let receipt = GithubPrResult {
            url: "https://github.com/acme/repo/pull/7".to_string(),
            head_oid: "d".repeat(40),
            base_oid: "c".repeat(40),
            number: 7,
            base_ref_name: "main".to_string(),
            state: "OPEN".to_string(),
            is_draft: false,
            title: "title".to_string(),
            body: format!("body\n\n{marker}"),
            head_ref_name: "maco/effects/abcd".to_string(),
            head_repository_owner: "acme".to_string(),
            head_repository_name: "repo".to_string(),
            is_cross_repository: false,
            author: "bot".to_string(),
            created: false,
        };
        let observer = Arc::new(ScriptedObserver::new());
        observer.list.lock().expect("lock").push(receipt.clone());
        *observer.view.lock().expect("lock") = Some(receipt);
        let verifier = ParentPublicationProviderVerifier::with_injected_observer(
            PathBuf::from("/tmp/fresh-host"),
            observer.clone(),
        );
        let material = verifier
            .observe_bound_completion(&descriptor, "evt-reserve")
            .expect("material");
        assert_eq!(
            material.descriptor().payload_digest(),
            descriptor.payload_digest()
        );
        let calls = observer.calls.lock().expect("lock");
        assert!(calls.contains(&"gh_list"));
        assert!(calls.contains(&"gh_view"));
    }

    #[test]
    fn duplicate_github_candidates_refuse_observation() {
        let descriptor = sample_pr_descriptor("title", "body");
        let marker = match descriptor.operation() {
            PublicationEffectOperationV1::GithubPullRequest(fields) => fields.marker().to_string(),
            _ => panic!("pr descriptor"),
        };
        let receipt = GithubPrResult {
            url: "https://github.com/acme/repo/pull/7".to_string(),
            head_oid: "d".repeat(40),
            base_oid: "c".repeat(40),
            number: 7,
            base_ref_name: "main".to_string(),
            state: "OPEN".to_string(),
            is_draft: false,
            title: "title".to_string(),
            body: format!("body\n\n{marker}"),
            head_ref_name: "maco/effects/abcd".to_string(),
            head_repository_owner: "acme".to_string(),
            head_repository_name: "repo".to_string(),
            is_cross_repository: false,
            author: "bot".to_string(),
            created: false,
        };
        let observer = Arc::new(ScriptedObserver::new());
        observer.list.lock().expect("lock").push(receipt.clone());
        observer.list.lock().expect("lock").push(receipt.clone());
        *observer.view.lock().expect("lock") = Some(receipt);
        let verifier = ParentPublicationProviderVerifier::with_injected_observer(
            PathBuf::from("/tmp/fresh-host"),
            observer,
        );
        assert!(verifier
            .observe_bound_completion(&descriptor, "evt")
            .is_err());
    }
}
