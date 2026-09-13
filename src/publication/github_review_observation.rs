//! Authenticated, finite GitHub observation behind the existing private gh context.
//! All operations are fixed by `AuthenticatedGithubOperation`; caller data can
//! select only a repository-bound item, page number, or provider cursor.

use super::forge_transport::{
    ForgeComment, ForgeObservation, ForgeObservationRequest, ForgeReviewThread,
    ItemThreadObservation,
};
use super::*;

const MAX_ITEM_COMMENTS: usize = 1_024;
const MAX_REVIEW_THREADS: usize = 512;
const MAX_THREAD_COMMENTS: usize = 512;
const MAX_REVIEW_COMMENTS: usize = 4_096;

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct RestRepository {
    node_id: String,
    full_name: String,
    html_url: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct RestIssue {
    node_id: String,
    number: u64,
    html_url: String,
    updated_at: String,
    pull_request: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RestIssueComment {
    node_id: String,
    id: u64,
    html_url: String,
    body: Option<String>,
    created_at: String,
    user: Option<GithubApiActor>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlEnvelope<T> {
    data: Option<T>,
    errors: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlThreadData {
    repository: Option<GraphqlRepository>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlNodeData {
    node: Option<GraphqlThreadNode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GraphqlRepository {
    id: String,
    name_with_owner: String,
    url: String,
    pull_request: Option<GraphqlPullRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GraphqlParentRepository {
    id: String,
    name_with_owner: String,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GraphqlPullRequest {
    id: String,
    number: u64,
    head_ref_oid: String,
    base_ref_oid: String,
    review_threads: GraphqlConnection<GraphqlThreadNode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GraphqlThreadParent {
    id: String,
    number: u64,
    head_ref_oid: String,
    base_ref_oid: String,
    repository: GraphqlParentRepository,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GraphqlThreadNode {
    id: String,
    is_resolved: bool,
    #[serde(default)]
    pull_request: Option<GraphqlThreadParent>,
    comments: GraphqlConnection<GraphqlReviewComment>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GraphqlConnection<T> {
    nodes: Vec<T>,
    page_info: GraphqlPageInfo,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GraphqlPageInfo {
    has_next_page: bool,
    end_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum GraphqlDatabaseId {
    Number(u64),
    Text(String),
}

impl GraphqlDatabaseId {
    fn positive(self) -> Result<u64> {
        let value = match self {
            Self::Number(number) => number,
            Self::Text(text) => {
                if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    bail!("GitHub review comment database id was not a positive decimal integer");
                }
                text.parse()
                    .context("GitHub review comment database id overflowed")?
            }
        };
        if value == 0 {
            bail!("GitHub review comment omitted a positive database id");
        }
        Ok(value)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GraphqlReviewComment {
    id: String,
    full_database_id: Option<GraphqlDatabaseId>,
    url: String,
    body: String,
    created_at: String,
    author: Option<GraphqlActor>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlActor {
    id: String,
    login: String,
    #[serde(rename = "__typename")]
    kind: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ResolvedItem {
    item: ForgeItem,
    updated_at: ForgeTimestamp,
}

fn parse_graphql<T: serde::de::DeserializeOwned>(json: &str, label: &str) -> Result<T> {
    let envelope: GraphqlEnvelope<T> = parse_authenticated_github_json(json, label)?;
    if envelope
        .errors
        .as_ref()
        .is_some_and(|errors| !errors.is_empty())
    {
        bail!("{label} returned GraphQL errors");
    }
    envelope
        .data
        .context("GitHub GraphQL response omitted data")
}

fn verify_bound_origin(repo: &Path, expected: &GithubRepositoryIdentity) -> Result<()> {
    let local = crate::git_repository::discover(repo)
        .context("discover repository for GitHub observation")?;
    let actual = github_repository_identity(&remote_url(&local, "origin")?)?;
    if &actual != expected {
        bail!("GitHub observation selector differs from the local origin repository");
    }
    Ok(())
}

fn repository_from_rest(
    rest: &RestRepository,
    expected: &GithubRepositoryIdentity,
) -> Result<ForgeRepository> {
    let owner_name = format!("{}/{}", expected.owner, expected.name);
    if rest.full_name.to_ascii_lowercase() != owner_name
        || !rest
            .html_url
            .eq_ignore_ascii_case(&format!("https://{}", expected.selector()))
    {
        bail!("GitHub repository identity does not match its exact origin selector");
    }
    ForgeRepository::new(
        "github",
        expected.selector(),
        github_node_object_id(ProviderObjectKind::Repository, &rest.node_id)?,
    )
}

fn resolve_repository_with(
    transport: &GithubPullRequestMergeTransport,
    mut fetch: impl FnMut(&str, AuthenticatedGithubOperation) -> Result<String>,
) -> Result<ForgeRepository> {
    let rest: RestRepository = parse_authenticated_github_json(
        &fetch(
            "gh review repository identity",
            AuthenticatedGithubOperation::Repository,
        )?,
        "GitHub review repository identity",
    )?;
    repository_from_rest(&rest, &transport.repository)
}

fn repository_from_pull(
    pull: &GithubApiPullRequest,
    expected: &GithubRepositoryIdentity,
) -> Result<ForgeRepository> {
    let base = pull
        .base
        .repo
        .as_ref()
        .context("GitHub PR omitted base repository identity")?;
    let owner_name = format!("{}/{}", expected.owner, expected.name);
    if base.full_name.to_ascii_lowercase() != owner_name {
        bail!("GitHub PR base repository differs from the exact origin selector");
    }
    ForgeRepository::new(
        "github",
        expected.selector(),
        github_node_object_id(ProviderObjectKind::Repository, &base.node_id)?,
    )
}

fn resolve_item_with(
    transport: &GithubPullRequestMergeTransport,
    kind: ForgeItemKind,
    number: u64,
    mut fetch: impl FnMut(&str, AuthenticatedGithubOperation) -> Result<String>,
) -> Result<ResolvedItem> {
    validate_authenticated_github_number(number)?;
    let expected = &transport.repository;
    match kind {
        ForgeItemKind::PullRequest => {
            let pull: GithubApiPullRequest = parse_authenticated_github_json(
                &fetch(
                    "gh review PR identity",
                    AuthenticatedGithubOperation::PullRequest { number },
                )?,
                "GitHub review PR identity",
            )?;
            transport.validate_pull_request_repository(&pull, number)?;
            validate_authenticated_github_oid(&pull.head.sha)?;
            validate_authenticated_github_oid(&pull.base.sha)?;
            let repository = repository_from_pull(&pull, expected)?;
            Ok(ResolvedItem {
                item: ForgeItem::new(
                    repository,
                    ForgeItemKind::PullRequest,
                    number,
                    github_node_object_id(ProviderObjectKind::Item, &pull.node_id)?,
                    format!("github-pr-{number}-{}", pull.head.sha),
                    Some(pull.head.sha),
                    Some(pull.base.sha),
                )?,
                updated_at: ForgeTimestamp::new(pull.updated_at)?,
            })
        }
        ForgeItemKind::Issue => {
            let repository: RestRepository = parse_authenticated_github_json(
                &fetch(
                    "gh review repository identity",
                    AuthenticatedGithubOperation::Repository,
                )?,
                "GitHub review repository identity",
            )?;
            let repository = repository_from_rest(&repository, expected)?;
            let issue: RestIssue = parse_authenticated_github_json(
                &fetch(
                    "gh review issue identity",
                    AuthenticatedGithubOperation::Issue { number },
                )?,
                "GitHub review issue identity",
            )?;
            if issue.number != number || issue.pull_request.is_some() {
                bail!("GitHub issue endpoint returned a different item kind or number");
            }
            validate_github_issue_receipt_url(&issue.html_url, expected, number)?;
            let updated_at = ForgeTimestamp::new(issue.updated_at)?;
            Ok(ResolvedItem {
                item: ForgeItem::new(
                    repository,
                    ForgeItemKind::Issue,
                    number,
                    github_node_object_id(ProviderObjectKind::Item, &issue.node_id)?,
                    format!(
                        "github-issue-{number}-{}",
                        sha256_hex(updated_at.as_str().as_bytes())
                    ),
                    None,
                    None,
                )?,
                updated_at,
            })
        }
    }
}

struct GithubCommentIdentity<'a> {
    node_id: &'a str,
    database_id: u64,
}

fn make_comment(
    item: &ForgeItem,
    identity: GithubCommentIdentity<'_>,
    url: String,
    body: String,
    created_at: ForgeTimestamp,
    author: ForgeActor,
    review: bool,
) -> Result<ForgeComment> {
    if identity.database_id == 0 {
        bail!("GitHub comment omitted a positive database id");
    }
    let fragment = if review {
        format!("discussion_r{}", identity.database_id)
    } else {
        format!("issuecomment-{}", identity.database_id)
    };
    let (base_url, actual_fragment) = url
        .split_once('#')
        .context("GitHub comment URL omitted its exact provider fragment")?;
    if actual_fragment != fragment || author.provider_id() != "github" {
        bail!("GitHub comment URL or author was not bound to the exact observed item");
    }
    let repository =
        github_repository_identity_from_selector(item.repository().canonical_locator())?;
    match item.kind() {
        ForgeItemKind::Issue if !review => {
            validate_github_issue_receipt_url(base_url, &repository, item.number())?;
        }
        ForgeItemKind::PullRequest => {
            validate_github_receipt_url(base_url, &repository, item.number())?;
        }
        ForgeItemKind::Issue => bail!("GitHub review comment did not belong to a pull request"),
    }
    ForgeComment::new(
        github_node_object_id(ProviderObjectKind::Comment, identity.node_id)?,
        author,
        body,
        url,
        created_at,
    )
}

fn collect_item_comments(
    item: &ForgeItem,
    mut fetch: impl FnMut(&str, AuthenticatedGithubOperation) -> Result<String>,
) -> Result<Vec<ForgeComment>> {
    let mut result = Vec::new();
    for page in 1..=AUTHENTICATED_GITHUB_MAX_PAGES {
        let label = format!("gh review item comments page {page}");
        let raw: Vec<RestIssueComment> = parse_authenticated_github_json(
            &fetch(
                &label,
                AuthenticatedGithubOperation::ItemComments {
                    number: item.number(),
                    page,
                },
            )?,
            &label,
        )?;
        if raw.len() > AUTHENTICATED_GITHUB_PAGE_SIZE {
            bail!("GitHub issue comments returned an oversized page");
        }
        let count = raw.len();
        for comment in raw {
            let actor = github_api_actor(
                comment
                    .user
                    .as_ref()
                    .context("GitHub issue comment omitted author")?,
            )?;
            result.push(make_comment(
                item,
                GithubCommentIdentity {
                    node_id: &comment.node_id,
                    database_id: comment.id,
                },
                comment.html_url,
                comment.body.context("GitHub issue comment omitted body")?,
                ForgeTimestamp::new(comment.created_at)?,
                actor,
                false,
            )?);
        }
        if result.len() > MAX_ITEM_COMMENTS {
            bail!("GitHub issue comments exceeded their finite count bound");
        }
        if count < AUTHENTICATED_GITHUB_PAGE_SIZE {
            return Ok(result);
        }
    }
    bail!("GitHub issue comments exceeded finite pagination")
}

fn graphql_actor(actor: GraphqlActor) -> Result<ForgeActor> {
    let kind = match actor.kind.as_str() {
        "User" => ReportedActorKind::Human,
        "Bot" => ReportedActorKind::Bot,
        "Organization" => ReportedActorKind::Organization,
        "Mannequin" => ReportedActorKind::Unknown,
        _ => bail!("GitHub review comment returned an unknown actor type"),
    };
    ForgeActor::new(
        "github",
        github_node_object_id(ProviderObjectKind::Actor, &actor.id)?,
        actor.login.to_ascii_lowercase(),
        kind,
    )
}

fn graphql_comment(item: &ForgeItem, comment: GraphqlReviewComment) -> Result<ForgeComment> {
    let database_id = comment
        .full_database_id
        .context("GitHub review comment omitted fullDatabaseId")?
        .positive()?;
    let actor = graphql_actor(
        comment
            .author
            .context("GitHub review comment omitted author")?,
    )?;
    make_comment(
        item,
        GithubCommentIdentity {
            node_id: &comment.id,
            database_id,
        },
        comment.url,
        comment.body,
        ForgeTimestamp::new(comment.created_at)?,
        actor,
        true,
    )
}

fn next_cursor(
    page: &GraphqlPageInfo,
    previous: Option<&str>,
    count: usize,
    label: &str,
) -> Result<Option<String>> {
    if !page.has_next_page {
        return Ok(None);
    }
    if count == 0 {
        bail!("{label} reported an empty non-final page");
    }
    let cursor = page
        .end_cursor
        .as_deref()
        .context("GitHub GraphQL page omitted continuation cursor")?;
    validate_authenticated_github_graphql_value(cursor, label)?;
    if previous == Some(cursor) {
        bail!("{label} repeated its continuation cursor");
    }
    Ok(Some(cursor.to_string()))
}

fn validate_graphql_repository(id: &str, name: &str, url: &str, item: &ForgeItem) -> Result<()> {
    let expected = item.repository();
    if github_node_object_id(ProviderObjectKind::Repository, id)?
        != *expected.provider_repository_id()
        || name.to_ascii_lowercase()
            != expected
                .canonical_locator()
                .split_once('/')
                .map(|(_, name)| name)
                .unwrap_or_default()
        || !url.eq_ignore_ascii_case(&format!("https://{}", expected.canonical_locator()))
    {
        bail!("GitHub GraphQL returned a different bound repository");
    }
    Ok(())
}

fn validate_graphql_pull(
    id: &str,
    number: u64,
    head: &str,
    base: &str,
    item: &ForgeItem,
) -> Result<()> {
    if github_node_object_id(ProviderObjectKind::Item, id)? != *item.provider_item_id()
        || number != item.number()
        || Some(head) != item.head_oid()
        || Some(base) != item.base_oid()
    {
        bail!("GitHub GraphQL returned a different exact pull request");
    }
    Ok(())
}

fn collect_thread_comments(
    item: &ForgeItem,
    thread_id: &str,
    expected_resolved: bool,
    first: GraphqlConnection<GraphqlReviewComment>,
    mut fetch: impl FnMut(&str, AuthenticatedGithubOperation) -> Result<String>,
) -> Result<Vec<ForgeComment>> {
    let mut comments = Vec::new();
    let mut cursor = None;
    let mut connection = first;
    for page in 1..=AUTHENTICATED_GITHUB_MAX_PAGES {
        let count = connection.nodes.len();
        if count > AUTHENTICATED_GITHUB_PAGE_SIZE {
            bail!("GitHub review thread returned an oversized comment page");
        }
        for comment in connection.nodes {
            comments.push(graphql_comment(item, comment)?);
        }
        if comments.len() > MAX_THREAD_COMMENTS {
            bail!("GitHub review thread exceeded its finite comment bound");
        }
        let Some(next) = next_cursor(
            &connection.page_info,
            cursor.as_deref(),
            count,
            "GitHub review thread",
        )?
        else {
            return Ok(comments);
        };
        if page == AUTHENTICATED_GITHUB_MAX_PAGES {
            break;
        }
        let label = format!("gh review thread comments page {}", page + 1);
        let data: GraphqlNodeData = parse_graphql(
            &fetch(
                &label,
                AuthenticatedGithubOperation::ReviewThreadComments {
                    thread_id: thread_id.to_string(),
                    after: Some(next.clone()),
                },
            )?,
            &label,
        )?;
        let node = data
            .node
            .context("GitHub review thread node disappeared during pagination")?;
        if node.id != thread_id || node.is_resolved != expected_resolved {
            bail!("GitHub review thread identity or resolution changed during pagination");
        }
        let parent = node
            .pull_request
            .context("GitHub review thread omitted parent PR")?;
        validate_graphql_repository(
            &parent.repository.id,
            &parent.repository.name_with_owner,
            &parent.repository.url,
            item,
        )?;
        validate_graphql_pull(
            &parent.id,
            parent.number,
            &parent.head_ref_oid,
            &parent.base_ref_oid,
            item,
        )?;
        cursor = Some(next);
        connection = node.comments;
    }
    bail!("GitHub review thread pagination exceeded its finite page bound")
}

fn collect_review_threads(
    item: &ForgeItem,
    mut fetch: impl FnMut(&str, AuthenticatedGithubOperation) -> Result<String>,
) -> Result<Vec<ForgeReviewThread>> {
    if item.kind() != ForgeItemKind::PullRequest {
        bail!("GitHub review threads require a pull request");
    }
    let mut threads = Vec::new();
    let mut thread_ids = BTreeSet::new();
    let mut total_comments = 0_usize;
    let mut cursor = None;
    for page in 1..=AUTHENTICATED_GITHUB_MAX_PAGES {
        let label = format!("gh review threads page {page}");
        let data: GraphqlThreadData = parse_graphql(
            &fetch(
                &label,
                AuthenticatedGithubOperation::ReviewThreads {
                    number: item.number(),
                    after: cursor.clone(),
                },
            )?,
            &label,
        )?;
        let repository = data
            .repository
            .context("GitHub GraphQL omitted repository")?;
        validate_graphql_repository(
            &repository.id,
            &repository.name_with_owner,
            &repository.url,
            item,
        )?;
        let pull = repository
            .pull_request
            .context("GitHub GraphQL omitted exact PR")?;
        validate_graphql_pull(
            &pull.id,
            pull.number,
            &pull.head_ref_oid,
            &pull.base_ref_oid,
            item,
        )?;
        let count = pull.review_threads.nodes.len();
        if count > AUTHENTICATED_GITHUB_PAGE_SIZE {
            bail!("GitHub review threads returned an oversized page");
        }
        let page_info = pull.review_threads.page_info;
        for thread in pull.review_threads.nodes {
            validate_authenticated_github_graphql_value(&thread.id, "review thread id")?;
            if !thread_ids.insert(thread.id.clone()) {
                bail!("GitHub review threads repeated a provider thread id");
            }
            let comments = collect_thread_comments(
                item,
                &thread.id,
                thread.is_resolved,
                thread.comments,
                &mut fetch,
            )?;
            total_comments = total_comments
                .checked_add(comments.len())
                .context("GitHub review comment count overflowed")?;
            if total_comments > MAX_REVIEW_COMMENTS {
                bail!("GitHub review comments exceeded their aggregate bound");
            }
            threads.push(ForgeReviewThread::new(
                github_node_object_id(ProviderObjectKind::ReviewThread, &thread.id)?,
                thread.is_resolved,
                comments,
            )?);
            if threads.len() > MAX_REVIEW_THREADS {
                bail!("GitHub review threads exceeded their finite count bound");
            }
        }
        let next = next_cursor(
            &page_info,
            cursor.as_deref(),
            count,
            "GitHub review threads",
        )?;
        match next {
            Some(next) => cursor = Some(next),
            None => return Ok(threads),
        }
    }
    bail!("GitHub review threads exceeded finite pagination")
}

fn observe_item_thread_with(
    transport: &GithubPullRequestMergeTransport,
    expected: &ForgeItem,
    mut fetch: impl FnMut(&str, AuthenticatedGithubOperation) -> Result<String>,
) -> Result<ForgeObservation> {
    let initial = resolve_item_with(transport, expected.kind(), expected.number(), &mut fetch)?;
    if &initial.item != expected {
        bail!("GitHub item-thread request did not match authenticated provider identity");
    }
    let comments = collect_item_comments(expected, &mut fetch)?;
    let final_item = resolve_item_with(transport, expected.kind(), expected.number(), &mut fetch)?;
    if final_item != initial {
        bail!("GitHub item identity or source revision changed during thread observation");
    }
    let observed_at = comments.iter().fold(initial.updated_at, |latest, comment| {
        latest.max(comment.created_at().clone())
    });
    Ok(ForgeObservation::ItemThread(ItemThreadObservation::new(
        expected.clone(),
        observed_at,
        comments,
    )?))
}

pub(super) fn resolve_item(
    repo: &Path,
    selector: &str,
    kind: ForgeItemKind,
    number: u64,
) -> Result<ForgeItem> {
    let transport = GithubPullRequestMergeTransport::new(repo, selector)?;
    verify_bound_origin(repo, &transport.repository)?;
    let item = resolve_item_with(&transport, kind, number, |label, operation| {
        transport.json(label, operation)
    })?
    .item;
    verify_bound_origin(repo, &transport.repository)?;
    Ok(item)
}

pub(super) fn resolve_repository(repo: &Path, selector: &str) -> Result<ForgeRepository> {
    let transport = GithubPullRequestMergeTransport::new(repo, selector)?;
    verify_bound_origin(repo, &transport.repository)?;
    let repository = resolve_repository_with(&transport, |label, operation| {
        transport.json(label, operation)
    })?;
    verify_bound_origin(repo, &transport.repository)?;
    Ok(repository)
}

pub(super) fn observe(
    repo: &Path,
    selector: &str,
    request: &ForgeObservationRequest,
) -> Result<ForgeObservation> {
    let transport = GithubPullRequestMergeTransport::new(repo, selector)?;
    verify_bound_origin(repo, &transport.repository)?;
    let expected = request.item();
    if expected.repository().canonical_locator() != transport.repository.selector() {
        bail!("GitHub observation request selected a different origin repository");
    }
    let observation = match request {
        ForgeObservationRequest::ItemThread(_) => {
            observe_item_thread_with(&transport, expected, |label, operation| {
                transport.json(label, operation)
            })
        }
        ForgeObservationRequest::PullRequestReviewSnapshot(_) => {
            let truth = transport.observe_number(expected.number())?;
            if truth.snapshot.item() != expected {
                bail!(
                    "GitHub review request did not match authenticated PR identity, head, and base"
                );
            }
            let threads = collect_review_threads(expected, |label, operation| {
                transport.json(label, operation)
            })?;
            let confirmed = resolve_item_with(
                &transport,
                ForgeItemKind::PullRequest,
                expected.number(),
                |label, operation| transport.json(label, operation),
            )?;
            if &confirmed.item != expected
                || confirmed.updated_at.as_str() != truth.source_updated_at
            {
                bail!("GitHub PR identity or source revision changed during review observation");
            }
            let observed_at = threads
                .iter()
                .flat_map(|thread| thread.comments())
                .fold(truth.snapshot.observed_at().clone(), |latest, comment| {
                    latest.max(comment.created_at().clone())
                });
            Ok(ForgeObservation::PullRequestReviewSnapshot(
                PullRequestReviewSnapshot::new(
                    expected.clone(),
                    observed_at,
                    truth.snapshot.reviews().to_vec(),
                    threads,
                    truth.snapshot.checks().to_vec(),
                )?,
            ))
        }
    }?;
    verify_bound_origin(repo, &transport.repository)?;
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::collections::VecDeque;

    const SELECTOR: &str = "github.com/meta-develop/maco";
    const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BASE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const UPDATED: &str = "2026-08-16T01:02:03Z";

    fn transport() -> GithubPullRequestMergeTransport {
        GithubPullRequestMergeTransport::new(Path::new("."), SELECTOR).expect("selector")
    }

    fn repository() -> ForgeRepository {
        ForgeRepository::new(
            "github",
            SELECTOR,
            github_node_object_id(ProviderObjectKind::Repository, "R_repo").expect("repo id"),
        )
        .expect("repository")
    }

    fn issue() -> ForgeItem {
        ForgeItem::new(
            repository(),
            ForgeItemKind::Issue,
            89,
            github_node_object_id(ProviderObjectKind::Item, "I_issue").expect("item id"),
            format!("github-issue-89-{}", sha256_hex(UPDATED.as_bytes())),
            None,
            None,
        )
        .expect("issue")
    }

    fn mixed_case_repository_issue() -> ForgeItem {
        let repository = ForgeRepository::new(
            "github",
            "github.com/meta-develop/multi-agent_coding_orchestrator",
            github_node_object_id(ProviderObjectKind::Repository, "R_actual_shape")
                .expect("repository id"),
        )
        .expect("repository");
        ForgeItem::new(
            repository,
            ForgeItemKind::Issue,
            6,
            github_node_object_id(ProviderObjectKind::Item, "I_actual_shape").expect("item id"),
            "github-issue-6-revision",
            None,
            None,
        )
        .expect("issue")
    }

    fn pr() -> ForgeItem {
        ForgeItem::new(
            repository(),
            ForgeItemKind::PullRequest,
            90,
            github_node_object_id(ProviderObjectKind::Item, "PR_review").expect("item id"),
            format!("github-pr-90-{HEAD}"),
            Some(HEAD.to_string()),
            Some(BASE.to_string()),
        )
        .expect("PR")
    }

    fn rest_repository() -> Value {
        json!({"node_id":"R_repo", "full_name":"meta-develop/maco",
            "html_url":"https://github.com/meta-develop/maco"})
    }

    #[test]
    fn repository_identity_read_is_fixed_and_distinguishes_provider_ids() {
        let mut operations = 0;
        let observed = resolve_repository_with(&transport(), |_, operation| {
            assert!(matches!(
                operation,
                AuthenticatedGithubOperation::Repository
            ));
            operations += 1;
            Ok(rest_repository().to_string())
        })
        .unwrap();
        assert_eq!(observed, repository());
        assert_eq!(operations, 1);

        let mut foreign = rest_repository();
        foreign["node_id"] = json!("R_other");
        let foreign_observed = resolve_repository_with(&transport(), |_, operation| {
            assert!(matches!(
                operation,
                AuthenticatedGithubOperation::Repository
            ));
            Ok(foreign.to_string())
        })
        .unwrap();
        assert_ne!(
            foreign_observed.provider_repository_id(),
            repository().provider_repository_id()
        );

        let mut wrong_name = rest_repository();
        wrong_name["full_name"] = json!("foreign/project");
        assert!(resolve_repository_with(&transport(), |_, _| Ok(wrong_name.to_string())).is_err());
    }

    fn rest_issue() -> Value {
        json!({"node_id":"I_issue", "number":89,
            "html_url":"https://github.com/meta-develop/maco/issues/89",
            "updated_at":UPDATED})
    }

    fn rest_comment(id: u64) -> Value {
        json!({"node_id":format!("IC_{id}"), "id":id,
            "html_url":format!("https://github.com/meta-develop/maco/issues/89#issuecomment-{id}"),
            "body":"observed", "created_at":"2026-08-15T01:02:03Z",
            "user":{"node_id":"U_writer", "login":"writer", "type":"User"}})
    }

    fn page(next: Option<&str>) -> Value {
        json!({"hasNextPage":next.is_some(), "endCursor":next})
    }

    fn graphql_comment(id: u64) -> Value {
        json!({"id":format!("RC_{id}"), "fullDatabaseId":id.to_string(),
            "url":format!("https://github.com/meta-develop/maco/pull/90#discussion_r{id}"),
            "body":"review evidence", "createdAt":"2026-08-15T01:02:03Z",
            "author":{"id":"U_reviewer", "login":"reviewer", "__typename":"User"}})
    }

    fn graphql_repository() -> Value {
        json!({"id":"R_repo", "nameWithOwner":"meta-develop/maco",
            "url":"https://github.com/meta-develop/maco"})
    }

    fn graphql_pr_parent() -> Value {
        json!({"id":"PR_review", "number":90, "headRefOid":HEAD,
            "baseRefOid":BASE, "repository":graphql_repository()})
    }

    fn thread(id: &str, resolved: bool, comments: Vec<Value>, next: Option<&str>) -> Value {
        json!({"id":id, "isResolved":resolved,
            "comments":{"nodes":comments, "pageInfo":page(next)}})
    }

    fn thread_page(threads: Vec<Value>, next: Option<&str>) -> Value {
        let mut repository = graphql_repository();
        repository["pullRequest"] = json!({"id":"PR_review", "number":90,
            "headRefOid":HEAD, "baseRefOid":BASE,
            "reviewThreads":{"nodes":threads, "pageInfo":page(next)}});
        json!({"data":{"repository":repository}})
    }

    fn thread_comment_page(
        id: &str,
        resolved: bool,
        comments: Vec<Value>,
        next: Option<&str>,
    ) -> Value {
        let mut node = thread(id, resolved, comments, next);
        node["pullRequest"] = graphql_pr_parent();
        json!({"data":{"node":node}})
    }

    #[test]
    fn finite_operations_keep_fixed_paths_documents_and_bounded_cursors() {
        let repository = transport().repository;
        let (args, input) = AuthenticatedGithubOperation::ItemComments {
            number: 89,
            page: 2,
        }
        .command(&repository)
        .expect("fixed item comment page");
        let args = args
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "api",
                "--method",
                "GET",
                "repos/meta-develop/maco/issues/89/comments?per_page=100&page=2",
            ]
            .map(str::to_string)
            .to_vec()
        );
        assert!(matches!(input, StdinMode::Null));

        let (args, input) = AuthenticatedGithubOperation::ReviewThreads {
            number: 90,
            after: Some("cursor-safe".to_string()),
        }
        .command(&repository)
        .expect("fixed GraphQL page");
        let args = args
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(args[0], "api");
        assert_eq!(args[1], "graphql");
        assert!(args
            .iter()
            .any(|arg| arg == &format!("query={GITHUB_REVIEW_THREADS_QUERY}")));
        for query in [
            GITHUB_REVIEW_THREADS_QUERY,
            GITHUB_REVIEW_THREAD_COMMENTS_QUERY,
        ] {
            assert!(query.contains("author{login __typename ... on Node{id}}"));
            assert!(!query.contains("author{id"));
        }
        assert!(args.iter().any(|arg| arg == "after=cursor-safe"));
        assert!(matches!(input, StdinMode::Null));
        assert!(AuthenticatedGithubOperation::ReviewThreads {
            number: 90,
            after: Some("unsafe\nnext".to_string()),
        }
        .command(&repository)
        .is_err());
        assert!(AuthenticatedGithubOperation::ItemComments {
            number: 89,
            page: 0
        }
        .command(&repository)
        .is_err());
    }

    #[test]
    fn mixed_case_rest_and_graphql_comment_urls_keep_exact_item_binding() {
        let real_issue = mixed_case_repository_issue();
        let rest_url = "https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/6#issuecomment-4991156337";
        let mut rest = rest_comment(4_991_156_337);
        rest["html_url"] = json!(rest_url);
        let comments = collect_item_comments(&real_issue, |_, operation| {
            assert!(matches!(
                operation,
                AuthenticatedGithubOperation::ItemComments { number: 6, page: 1 }
            ));
            Ok(json!([rest.clone()]).to_string())
        })
        .expect("provider-preserved repository path case");
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].url(), rest_url);

        let mut review = graphql_comment(202);
        review["url"] = json!("https://github.com/Meta-Develop/MaCo/pull/90#discussion_r202");
        let comment: GraphqlReviewComment =
            serde_json::from_value(review.clone()).expect("review comment");
        assert!(super::graphql_comment(&pr(), comment).is_ok());

        for invalid in [
            "https://github.com/Meta-Develop/Foreign/issues/6#issuecomment-4991156337",
            "https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/7#issuecomment-4991156337",
            "https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/pull/6#issuecomment-4991156337",
            "https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/6#issuecomment-9",
            "https://evil.example/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/6#issuecomment-4991156337",
        ] {
            let mut bad = rest_comment(4_991_156_337);
            bad["html_url"] = json!(invalid);
            assert!(collect_item_comments(&real_issue, |_, _| Ok(json!([bad.clone()]).to_string())).is_err(),
                "accepted wrong REST URL: {invalid}");
        }
        for invalid in [
            "https://github.com/Meta-Develop/Foreign/pull/90#discussion_r202",
            "https://github.com/Meta-Develop/MaCo/pull/91#discussion_r202",
            "https://github.com/Meta-Develop/MaCo/issues/90#discussion_r202",
            "https://github.com/Meta-Develop/MaCo/pull/90#issuecomment-202",
            "https://github.com/Meta-Develop/MaCo/pull/90#discussion_r203",
        ] {
            let mut bad = review.clone();
            bad["url"] = json!(invalid);
            let comment = serde_json::from_value(bad).expect("review comment");
            assert!(
                super::graphql_comment(&pr(), comment).is_err(),
                "accepted wrong GraphQL URL: {invalid}"
            );
        }
    }

    #[test]
    fn authenticated_issue_thread_collects_complete_pages_and_revalidates_identity() {
        let mut calls = Vec::new();
        let observed = observe_item_thread_with(&transport(), &issue(), |_, operation| {
            let value = match operation {
                AuthenticatedGithubOperation::Repository => rest_repository(),
                AuthenticatedGithubOperation::Issue { number: 89 } => rest_issue(),
                AuthenticatedGithubOperation::ItemComments {
                    number: 89,
                    page: 1,
                } => Value::Array((1..=100).map(rest_comment).collect()),
                AuthenticatedGithubOperation::ItemComments {
                    number: 89,
                    page: 2,
                } => {
                    json!([rest_comment(101)])
                }
                _ => panic!("unexpected GitHub operation"),
            };
            calls.push(value.clone());
            Ok(value.to_string())
        })
        .expect("authenticated finite issue observation");
        let ForgeObservation::ItemThread(thread) = observed else {
            panic!("item thread")
        };
        assert_eq!(thread.item(), &issue());
        assert_eq!(thread.comments().len(), 101);
        assert_eq!(calls.len(), 6); // identity before and after both comment pages

        let mut issues = 0;
        let error = observe_item_thread_with(&transport(), &issue(), |_, operation| {
            Ok(match operation {
                AuthenticatedGithubOperation::Repository => rest_repository(),
                AuthenticatedGithubOperation::Issue { .. } => {
                    issues += 1;
                    let mut value = rest_issue();
                    if issues == 2 {
                        value["updated_at"] = json!("2026-08-17T01:02:03Z");
                    }
                    value
                }
                AuthenticatedGithubOperation::ItemComments { .. } => json!([]),
                _ => panic!("unexpected GitHub operation"),
            }
            .to_string())
        })
        .expect_err("changed source must fail");
        assert!(error
            .to_string()
            .contains("changed during thread observation"));
    }

    #[test]
    fn authenticated_threads_collect_outer_and_nested_pages_with_resolution() {
        let mut operations = Vec::new();
        let threads = collect_review_threads(&pr(), |_, operation| {
            let value = match &operation {
                AuthenticatedGithubOperation::ReviewThreads {
                    number: 90,
                    after: None,
                } => thread_page(
                    vec![thread(
                        "T_one",
                        false,
                        vec![graphql_comment(201)],
                        Some("comments-one"),
                    )],
                    Some("threads-one"),
                ),
                AuthenticatedGithubOperation::ReviewThreadComments {
                    thread_id,
                    after: Some(after),
                } if thread_id == "T_one" && after == "comments-one" => {
                    thread_comment_page("T_one", false, vec![graphql_comment(202)], None)
                }
                AuthenticatedGithubOperation::ReviewThreads {
                    number: 90,
                    after: Some(after),
                } if after == "threads-one" => thread_page(
                    vec![thread("T_two", true, vec![graphql_comment(203)], None)],
                    None,
                ),
                _ => panic!("unexpected GitHub operation"),
            };
            operations.push(operation);
            Ok(value.to_string())
        })
        .expect("complete authenticated review threads");
        assert_eq!(operations.len(), 3);
        assert_eq!(threads.len(), 2);
        assert!(!threads[0].is_resolved());
        assert_eq!(threads[0].comments().len(), 2);
        assert!(threads[1].is_resolved());
    }

    #[test]
    fn item_comment_pages_reject_oversize_and_duplicate_provider_ids() {
        let oversized = collect_item_comments(&issue(), |_, operation| {
            assert!(matches!(
                operation,
                AuthenticatedGithubOperation::ItemComments { page: 1, .. }
            ));
            Ok(Value::Array((1..=101).map(rest_comment).collect()).to_string())
        });
        assert!(oversized
            .expect_err("oversized page")
            .to_string()
            .contains("oversized page"));

        let duplicate = observe_item_thread_with(&transport(), &issue(), |_, operation| {
            Ok(match operation {
                AuthenticatedGithubOperation::Repository => rest_repository(),
                AuthenticatedGithubOperation::Issue { .. } => rest_issue(),
                AuthenticatedGithubOperation::ItemComments { .. } => {
                    json!([rest_comment(1), rest_comment(1)])
                }
                _ => panic!("unexpected GitHub operation"),
            }
            .to_string())
        });
        assert!(duplicate.is_err());
    }

    #[test]
    fn review_threads_reject_foreign_parent_missing_actor_and_incomplete_cursor() {
        let valid = thread_page(
            vec![thread("T_one", false, vec![graphql_comment(201)], None)],
            None,
        );
        let mut cases = VecDeque::new();
        let mut wrong_repo = valid.clone();
        wrong_repo["data"]["repository"]["id"] = json!("R_foreign");
        cases.push_back(wrong_repo);
        let mut wrong_head = valid.clone();
        wrong_head["data"]["repository"]["pullRequest"]["headRefOid"] = json!(BASE);
        cases.push_back(wrong_head);
        let mut missing_actor = valid.clone();
        missing_actor["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"][0]
            ["comments"]["nodes"][0]["author"] = Value::Null;
        cases.push_back(missing_actor);
        let mut missing_actor_id = valid.clone();
        missing_actor_id["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"][0]
            ["comments"]["nodes"][0]["author"]
            .as_object_mut()
            .expect("actor")
            .remove("id");
        cases.push_back(missing_actor_id);
        let mut missing_cursor = valid.clone();
        missing_cursor["data"]["repository"]["pullRequest"]["reviewThreads"]["pageInfo"] =
            json!({"hasNextPage":true,"endCursor":null});
        cases.push_back(missing_cursor);
        let mut duplicate = valid;
        duplicate["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"] = json!([
            thread("T_one", false, vec![graphql_comment(201)], None),
            thread("T_one", false, vec![graphql_comment(202)], None)
        ]);
        cases.push_back(duplicate);
        let mut oversized = thread_page(Vec::new(), None);
        oversized["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"] = Value::Array(
            (0..101)
                .map(|index| thread(&format!("T_{index}"), false, Vec::new(), None))
                .collect(),
        );
        cases.push_back(oversized);
        for case in cases {
            let result = collect_review_threads(&pr(), |_, _| Ok(case.to_string()));
            assert!(
                result.is_err(),
                "accepted invalid GitHub review thread page: {case}"
            );
        }

        let wrong_parent = collect_review_threads(&pr(), |_, operation| {
            Ok(match operation {
                AuthenticatedGithubOperation::ReviewThreads { .. } => thread_page(
                    vec![thread(
                        "T_one",
                        false,
                        vec![graphql_comment(201)],
                        Some("next"),
                    )],
                    None,
                ),
                AuthenticatedGithubOperation::ReviewThreadComments { .. } => {
                    let mut page =
                        thread_comment_page("T_one", false, vec![graphql_comment(202)], None);
                    page["data"]["node"]["pullRequest"]["number"] = json!(91);
                    page
                }
                _ => panic!("unexpected GitHub operation"),
            }
            .to_string())
        });
        assert!(wrong_parent.is_err());
    }
}
