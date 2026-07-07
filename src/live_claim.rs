use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::{
    cmp::Ordering,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const CLAIMS_DIR: &str = ".agents/live/claims";
const TEMPLATE_FILE: &str = "CLAIM_TEMPLATE.md";
const DEFAULT_STALE_AFTER_MINUTES: u64 = 720;
const VALID_STATUSES: &[&str] = &["active", "blocked", "ready-for-review", "handoff", "done"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimsStatusReport {
    pub repo: PathBuf,
    pub claims_dir: PathBuf,
    pub now: String,
    pub claim_count: usize,
    pub lock_count: usize,
    pub claims: Vec<LiveClaimSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimSummary {
    pub claim_id: String,
    pub file: PathBuf,
    pub owner: Option<String>,
    pub status: Option<String>,
    pub is_lock: bool,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub heartbeat: Option<String>,
    pub stale_after_minutes: Option<u64>,
    pub owned_files: Vec<PathBuf>,
    pub liveness: LiveClaimLiveness,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimLiveness {
    pub state: String,
    pub reference_field: Option<String>,
    pub reference_timestamp: Option<String>,
    pub age_minutes: Option<i64>,
    pub stale_after_minutes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimsValidationReport {
    pub repo: PathBuf,
    pub claims_dir: PathBuf,
    pub valid: bool,
    pub claim_count: usize,
    pub issue_count: usize,
    pub claims: Vec<LiveClaimValidation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimValidation {
    pub claim_id: String,
    pub file: PathBuf,
    pub issues: Vec<LiveClaimIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimIssue {
    pub severity: String,
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimMutationReport {
    pub claim_id: String,
    pub file: PathBuf,
    pub actor: String,
    pub previous_status: Option<String>,
    pub status: Option<String>,
    pub updated: String,
    pub audit_entry: String,
    pub claim: LiveClaimSummary,
}

#[derive(Debug, Clone)]
pub struct LiveClock {
    raw: String,
    epoch_seconds: i64,
}

impl LiveClock {
    pub fn parse(value: &str) -> Result<Self> {
        let raw = clean_scalar(value);
        let epoch_seconds = parse_timestamp_seconds(&raw)
            .with_context(|| format!("failed to parse timestamp '{raw}'"))?;
        Ok(Self { raw, epoch_seconds })
    }

    pub fn now() -> Self {
        let epoch_seconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            Err(_) => 0,
        };
        Self {
            raw: format_epoch_seconds(epoch_seconds),
            epoch_seconds,
        }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

pub fn status(repo: impl AsRef<Path>, now: &LiveClock) -> Result<LiveClaimsStatusReport> {
    let repo = repo.as_ref().to_path_buf();
    let claims_dir = claims_dir(&repo);
    let claims = load_claims(&claims_dir, now)?;
    let lock_count = claims.iter().filter(|claim| claim.is_lock).count();
    Ok(LiveClaimsStatusReport {
        repo,
        claims_dir,
        now: now.raw.clone(),
        claim_count: claims.len(),
        lock_count,
        claims,
    })
}

pub fn validate(repo: impl AsRef<Path>, now: &LiveClock) -> Result<LiveClaimsValidationReport> {
    let repo = repo.as_ref().to_path_buf();
    let claims_dir = claims_dir(&repo);
    let claims = load_parsed_claims(&claims_dir)?;
    let mut validations = Vec::with_capacity(claims.len());
    let mut issue_count = 0usize;

    for claim in claims {
        let mut issues = Vec::new();
        push_required_issue(&mut issues, "claim_id", claim.claim_id.as_deref());
        push_required_issue(&mut issues, "owner", claim.owner.as_deref());
        push_required_issue(&mut issues, "status", claim.status.as_deref());
        if let Some(status) = &claim.status {
            if !VALID_STATUSES.contains(&status.as_str()) {
                issues.push(LiveClaimIssue {
                    severity: "error".to_string(),
                    field: "status".to_string(),
                    message: format!(
                        "status '{status}' is not one of {}",
                        VALID_STATUSES.join(", ")
                    ),
                });
            }
        }
        if claim.owned_files.is_empty() {
            issues.push(LiveClaimIssue {
                severity: "error".to_string(),
                field: "owned_files".to_string(),
                message: "claim must list at least one owned file or surface".to_string(),
            });
        }
        if claim.reference_timestamp().is_none() {
            issues.push(LiveClaimIssue {
                severity: "warning".to_string(),
                field: "heartbeat".to_string(),
                message: "claim has no heartbeat, updated, created, or date timestamp".to_string(),
            });
        }
        if claim.stale_after_minutes.is_none() {
            issues.push(LiveClaimIssue {
                severity: "warning".to_string(),
                field: "stale_after_minutes".to_string(),
                message: "claim has no stale-after value; liveness uses the default".to_string(),
            });
        }
        for warning in summary_from_parsed(&claim, now).warnings {
            issues.push(LiveClaimIssue {
                severity: "warning".to_string(),
                field: "liveness".to_string(),
                message: warning,
            });
        }
        issue_count = issue_count.saturating_add(issues.len());
        validations.push(LiveClaimValidation {
            claim_id: claim.display_id(),
            file: claim.file.clone(),
            issues,
        });
    }

    let valid = validations
        .iter()
        .all(|claim| claim.issues.iter().all(|issue| issue.severity != "error"));

    Ok(LiveClaimsValidationReport {
        repo,
        claims_dir,
        valid,
        claim_count: validations.len(),
        issue_count,
        claims: validations,
    })
}

pub fn heartbeat(
    repo: impl AsRef<Path>,
    claim_id: &str,
    actor: &str,
    now: &LiveClock,
) -> Result<LiveClaimMutationReport> {
    if actor.trim().is_empty() {
        bail!("heartbeat requires --by");
    }

    let claims_dir = claims_dir(repo.as_ref());
    let claim = find_claim(&claims_dir, claim_id)?;
    let previous_status = claim.status.clone();
    let audit_entry = format!("`{}` - `{}` heartbeat", now.raw(), actor);
    let content = fs::read_to_string(&claim.path)
        .with_context(|| format!("failed to read claim {}", claim.path.display()))?;
    let updated = update_claim_content(&content, &claim, now, None, &audit_entry)?;
    fs::write(&claim.path, updated)
        .with_context(|| format!("failed to write claim {}", claim.path.display()))?;
    mutation_report(
        repo.as_ref(),
        claim_id,
        actor,
        previous_status,
        now,
        audit_entry,
    )
}

pub fn override_release(
    repo: impl AsRef<Path>,
    claim_id: &str,
    actor: &str,
    reason: &str,
    now: &LiveClock,
) -> Result<LiveClaimMutationReport> {
    if actor.trim().is_empty() {
        bail!("override-release requires --by");
    }
    if reason.trim().is_empty() {
        bail!("override-release requires --reason");
    }

    let claims_dir = claims_dir(repo.as_ref());
    let claim = find_claim(&claims_dir, claim_id)?;
    let previous_status = claim.status.clone();
    let previous = previous_status
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let audit_entry = format!(
        "`{}` - `{}` override-release; previous status `{}`; reason: {}",
        now.raw(),
        actor,
        previous,
        reason.trim()
    );
    let content = fs::read_to_string(&claim.path)
        .with_context(|| format!("failed to read claim {}", claim.path.display()))?;
    let updated = update_claim_content(&content, &claim, now, Some("handoff"), &audit_entry)?;
    fs::write(&claim.path, updated)
        .with_context(|| format!("failed to write claim {}", claim.path.display()))?;
    mutation_report(
        repo.as_ref(),
        claim_id,
        actor,
        previous_status,
        now,
        audit_entry,
    )
}

fn mutation_report(
    repo: &Path,
    claim_id: &str,
    actor: &str,
    previous_status: Option<String>,
    now: &LiveClock,
    audit_entry: String,
) -> Result<LiveClaimMutationReport> {
    let claims_dir = claims_dir(repo);
    let claim = find_claim(&claims_dir, claim_id)?;
    let summary = summary_from_parsed(&claim, now);
    Ok(LiveClaimMutationReport {
        claim_id: summary.claim_id.clone(),
        file: summary.file.clone(),
        actor: actor.to_string(),
        previous_status,
        status: summary.status.clone(),
        updated: now.raw().to_string(),
        audit_entry,
        claim: summary,
    })
}

fn claims_dir(repo: &Path) -> PathBuf {
    repo.join(CLAIMS_DIR)
}

fn load_claims(claims_dir: &Path, now: &LiveClock) -> Result<Vec<LiveClaimSummary>> {
    Ok(load_parsed_claims(claims_dir)?
        .iter()
        .map(|claim| summary_from_parsed(claim, now))
        .collect())
}

fn load_parsed_claims(claims_dir: &Path) -> Result<Vec<ParsedClaim>> {
    let mut claims = Vec::new();
    let entries = match fs::read_dir(claims_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(claims),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read claims dir {}", claims_dir.display()));
        }
    };

    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "failed to read an entry from claims dir {}",
                claims_dir.display()
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("md") {
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some(TEMPLATE_FILE) {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read claim {}", path.display()))?;
        claims.push(parse_claim_file(path, &content));
    }
    claims.sort_by_key(|claim| claim.display_id());
    Ok(claims)
}

fn find_claim(claims_dir: &Path, claim_id: &str) -> Result<ParsedClaim> {
    let requested = clean_scalar(claim_id);
    for claim in load_parsed_claims(claims_dir)? {
        if claim.display_id() == requested {
            return Ok(claim);
        }
    }
    bail!("claim '{requested}' not found in {}", claims_dir.display())
}

#[derive(Debug, Clone)]
struct ParsedClaim {
    path: PathBuf,
    file: PathBuf,
    claim_id: Option<String>,
    owner: Option<String>,
    status: Option<String>,
    created: Option<String>,
    updated: Option<String>,
    heartbeat: Option<String>,
    date: Option<String>,
    stale_after_minutes: Option<u64>,
    owned_files: Vec<PathBuf>,
}

impl ParsedClaim {
    fn display_id(&self) -> String {
        self.claim_id.clone().unwrap_or_else(|| {
            self.file
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("unknown")
                .to_string()
        })
    }

    fn reference_timestamp(&self) -> Option<(&'static str, &str)> {
        self.heartbeat
            .as_deref()
            .map(|timestamp| ("heartbeat", timestamp))
            .or_else(|| {
                self.updated
                    .as_deref()
                    .map(|timestamp| ("updated", timestamp))
            })
            .or_else(|| {
                self.created
                    .as_deref()
                    .map(|timestamp| ("created", timestamp))
            })
            .or_else(|| self.date.as_deref().map(|timestamp| ("date", timestamp)))
    }
}

fn parse_claim_file(path: PathBuf, content: &str) -> ParsedClaim {
    let mut claim = ParsedClaim {
        file: PathBuf::from(
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(""),
        ),
        path,
        claim_id: None,
        owner: None,
        status: None,
        created: None,
        updated: None,
        heartbeat: None,
        date: None,
        stale_after_minutes: None,
        owned_files: Vec::new(),
    };
    let mut in_owned_files = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("# Claim:") {
            claim.claim_id = Some(clean_scalar(rest));
            continue;
        }

        let is_outer_bullet = line.starts_with("- ");
        let lower = trimmed.to_ascii_lowercase();
        if is_outer_bullet && lower.contains("owned files") {
            in_owned_files = true;
            continue;
        }
        if in_owned_files {
            if is_outer_bullet {
                in_owned_files = false;
            } else if let Some(path) = owned_file_from_line(trimmed) {
                claim.owned_files.push(path);
                continue;
            }
        }

        if let Some((key, value)) = field_from_line(trimmed) {
            match key.as_str() {
                "claim id" => claim.claim_id = Some(value),
                "owner" => claim.owner = Some(value),
                "status" => claim.status = Some(value),
                "created" => claim.created = Some(value),
                "updated" => claim.updated = Some(value),
                "heartbeat" => claim.heartbeat = Some(value),
                "date" => claim.date = Some(value),
                "stale after minutes" => claim.stale_after_minutes = value.parse::<u64>().ok(),
                _ => {}
            }
        }
    }
    claim.owned_files.sort();
    claim.owned_files.dedup();
    claim
}

fn field_from_line(line: &str) -> Option<(String, String)> {
    let body = line.strip_prefix("- ")?;
    let (key, value) = body.split_once(':')?;
    Some((key.trim().to_ascii_lowercase(), clean_scalar(value)))
}

fn owned_file_from_line(line: &str) -> Option<PathBuf> {
    let body = line.strip_prefix("- ")?;
    if let Some(after_first) = body.strip_prefix('`') {
        let (path, _) = after_first.split_once('`')?;
        return Some(PathBuf::from(path));
    }
    let candidate = body.split(':').next().unwrap_or(body).trim();
    if candidate.is_empty() {
        None
    } else {
        Some(PathBuf::from(clean_scalar(candidate)))
    }
}

fn summary_from_parsed(claim: &ParsedClaim, now: &LiveClock) -> LiveClaimSummary {
    let mut warnings = Vec::new();
    let stale_after_minutes = claim
        .stale_after_minutes
        .unwrap_or(DEFAULT_STALE_AFTER_MINUTES);
    let liveness = if let Some((field, timestamp)) = claim.reference_timestamp() {
        match parse_timestamp_seconds(timestamp) {
            Ok(reference_seconds) => {
                let age_minutes = (now.epoch_seconds - reference_seconds) / 60;
                let stale_after_i64 = i64::try_from(stale_after_minutes).unwrap_or(i64::MAX);
                let state = match age_minutes.cmp(&stale_after_i64) {
                    Ordering::Greater => "stale",
                    Ordering::Equal | Ordering::Less => "fresh",
                };
                LiveClaimLiveness {
                    state: state.to_string(),
                    reference_field: Some(field.to_string()),
                    reference_timestamp: Some(timestamp.to_string()),
                    age_minutes: Some(age_minutes),
                    stale_after_minutes: Some(stale_after_minutes),
                }
            }
            Err(error) => {
                warnings.push(format!("{field} timestamp is malformed: {error}"));
                LiveClaimLiveness {
                    state: "unknown".to_string(),
                    reference_field: Some(field.to_string()),
                    reference_timestamp: Some(timestamp.to_string()),
                    age_minutes: None,
                    stale_after_minutes: claim.stale_after_minutes,
                }
            }
        }
    } else {
        warnings.push("no heartbeat, updated, created, or date timestamp available".to_string());
        LiveClaimLiveness {
            state: "stale_risk".to_string(),
            reference_field: None,
            reference_timestamp: None,
            age_minutes: None,
            stale_after_minutes: claim.stale_after_minutes,
        }
    };

    if claim.stale_after_minutes.is_none() {
        warnings.push(format!(
            "missing stale-after value; using default {DEFAULT_STALE_AFTER_MINUTES} minutes"
        ));
    }

    let is_lock = matches!(claim.status.as_deref(), Some("active" | "blocked"));
    LiveClaimSummary {
        claim_id: claim.display_id(),
        file: claim.file.clone(),
        owner: claim.owner.clone(),
        status: claim.status.clone(),
        is_lock,
        created: claim.created.clone().or_else(|| claim.date.clone()),
        updated: claim.updated.clone(),
        heartbeat: claim.heartbeat.clone(),
        stale_after_minutes: claim.stale_after_minutes,
        owned_files: claim.owned_files.clone(),
        liveness,
        warnings,
    }
}

fn push_required_issue(issues: &mut Vec<LiveClaimIssue>, field: &str, value: Option<&str>) {
    if value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        issues.push(LiveClaimIssue {
            severity: "error".to_string(),
            field: field.to_string(),
            message: format!("missing required field '{field}'"),
        });
    }
}

fn update_claim_content(
    content: &str,
    claim: &ParsedClaim,
    now: &LiveClock,
    status: Option<&str>,
    audit_entry: &str,
) -> Result<String> {
    let mut lines = content.lines().map(ToString::to_string).collect::<Vec<_>>();
    ensure_field(&mut lines, "Claim ID", &claim.display_id());
    ensure_field(
        &mut lines,
        "Owner",
        claim.owner.as_deref().unwrap_or(&claim.display_id()),
    );
    ensure_field(
        &mut lines,
        "Created",
        claim
            .created
            .as_deref()
            .or(claim.date.as_deref())
            .unwrap_or(now.raw()),
    );
    ensure_field(&mut lines, "Updated", now.raw());
    ensure_field(&mut lines, "Heartbeat", now.raw());
    ensure_field(
        &mut lines,
        "Stale after minutes",
        &claim
            .stale_after_minutes
            .unwrap_or(DEFAULT_STALE_AFTER_MINUTES)
            .to_string(),
    );
    if let Some(status) = status {
        ensure_field(&mut lines, "Status", status);
    } else if let Some(existing) = &claim.status {
        ensure_field(&mut lines, "Status", existing);
    }
    ensure_owned_files_heading(&mut lines);
    let with_audit = append_audit_entry(&lines.join("\n"), audit_entry);
    Ok(format!("{with_audit}\n"))
}

fn ensure_field(lines: &mut Vec<String>, key: &str, value: &str) {
    let key_lower = key.to_ascii_lowercase();
    let new_line = format!("- {key}: `{}`", value.trim());
    for line in lines.iter_mut() {
        if let Some((candidate, _)) = field_from_line(line.trim()) {
            if candidate == key_lower {
                *line = new_line;
                return;
            }
        }
    }

    let insert_at = lines
        .iter()
        .position(|line| line.starts_with("- Owner:"))
        .map(|index| index.saturating_add(1))
        .or_else(|| lines.iter().position(|line| line.starts_with("- Date:")))
        .map(|index| index.saturating_add(1))
        .unwrap_or_else(|| {
            lines
                .iter()
                .position(|line| line.starts_with("# Claim:"))
                .map(|index| index.saturating_add(1))
                .unwrap_or(0)
        });
    lines.insert(insert_at, new_line);
}

fn ensure_owned_files_heading(lines: &mut Vec<String>) {
    let has_owned_files = lines
        .iter()
        .any(|line| line.to_ascii_lowercase().contains("owned files"));
    if has_owned_files {
        return;
    }
    let insert_at = lines
        .iter()
        .position(|line| line.starts_with("- Non-overlap"))
        .unwrap_or(lines.len());
    lines.insert(
        insert_at,
        "- Owned files, regions, devices, or services:".to_string(),
    );
    lines.insert(
        insert_at.saturating_add(1),
        "  - `<path-or-surface>`".to_string(),
    );
}

fn append_audit_entry(content: &str, audit_entry: &str) -> String {
    let entry = format!("- {audit_entry}");
    if content.contains("\n## Audit log") || content.starts_with("## Audit log") {
        let mut lines = content.lines().map(ToString::to_string).collect::<Vec<_>>();
        let audit_index = lines.iter().position(|line| line.trim() == "## Audit log");
        if let Some(index) = audit_index {
            let insert_at = lines
                .iter()
                .enumerate()
                .skip(index.saturating_add(1))
                .find_map(|(line_index, line)| {
                    if line.starts_with("## ") {
                        Some(line_index)
                    } else {
                        None
                    }
                })
                .unwrap_or(lines.len());
            if insert_at < lines.len() {
                if insert_at > 0 && !lines[insert_at.saturating_sub(1)].trim().is_empty() {
                    lines.insert(insert_at, String::new());
                }
                lines.insert(insert_at, entry);
                lines.insert(insert_at.saturating_add(1), String::new());
            } else if insert_at > 0 && !lines[insert_at.saturating_sub(1)].trim().is_empty() {
                lines.insert(insert_at, String::new());
                lines.insert(insert_at.saturating_add(1), entry);
            } else {
                lines.insert(insert_at, entry);
            }
            return lines.join("\n");
        }
    }

    if let Some(index) = content.find("\n## Public Boundary Reminder") {
        let (before, after) = content.split_at(index);
        format!("{before}\n## Audit log\n\n{entry}\n{after}")
    } else {
        format!("{content}\n\n## Audit log\n\n{entry}")
    }
}

fn clean_scalar(value: &str) -> String {
    value
        .trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim()
        .to_string()
}

fn parse_timestamp_seconds(value: &str) -> Result<i64> {
    let value = clean_scalar(value);
    if value.len() == 10 && value.as_bytes().get(4) == Some(&b'-') {
        let (year, month, day) = parse_date(&value)?;
        return days_from_civil(year, month, day)
            .checked_mul(86_400)
            .context("timestamp overflow");
    }

    let (date_part, time_part) = value
        .split_once('T')
        .or_else(|| value.split_once(' '))
        .context("timestamp must be YYYY-MM-DD or RFC3339-like date time")?;
    let (year, month, day) = parse_date(date_part)?;
    let (time_part, offset_seconds) = split_time_offset(time_part)?;
    let (hour, minute, second) = parse_time(time_part)?;
    let day_seconds = i64::from(hour)
        .checked_mul(3_600)
        .and_then(|value| value.checked_add(i64::from(minute) * 60))
        .and_then(|value| value.checked_add(i64::from(second)))
        .context("timestamp overflow")?;
    days_from_civil(year, month, day)
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(day_seconds))
        .and_then(|value| value.checked_sub(i64::from(offset_seconds)))
        .context("timestamp overflow")
}

fn parse_date(value: &str) -> Result<(i32, u32, u32)> {
    let parts = value.split('-').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("date must be YYYY-MM-DD");
    }
    let year = parts[0].parse::<i32>().context("invalid year")?;
    let month = parts[1].parse::<u32>().context("invalid month")?;
    let day = parts[2].parse::<u32>().context("invalid day")?;
    if !(1..=12).contains(&month) {
        bail!("month out of range");
    }
    if !(1..=days_in_month(year, month)).contains(&day) {
        bail!("day out of range");
    }
    Ok((year, month, day))
}

fn split_time_offset(value: &str) -> Result<(&str, i32)> {
    if let Some(time) = value.strip_suffix('Z') {
        return Ok((time, 0));
    }
    let offset_index = value
        .char_indices()
        .skip(1)
        .filter_map(|(index, character)| {
            if matches!(character, '+' | '-') {
                Some(index)
            } else {
                None
            }
        })
        .last();
    if let Some(index) = offset_index {
        let (time, offset) = value.split_at(index);
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        let offset_body = &offset[1..];
        let (hours, minutes) = offset_body
            .split_once(':')
            .context("UTC offset must be HH:MM")?;
        let hours = hours.parse::<i32>().context("invalid UTC offset hour")?;
        let minutes = minutes
            .parse::<i32>()
            .context("invalid UTC offset minute")?;
        if !(0..=23).contains(&hours) || !(0..=59).contains(&minutes) {
            bail!("UTC offset out of range");
        }
        return Ok((time, sign * (hours * 3_600 + minutes * 60)));
    }
    Ok((value, 0))
}

fn parse_time(value: &str) -> Result<(u32, u32, u32)> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("time must be HH:MM:SS");
    }
    let hour = parts[0].parse::<u32>().context("invalid hour")?;
    let minute = parts[1].parse::<u32>().context("invalid minute")?;
    let second_part = parts[2].split('.').next().unwrap_or(parts[2]);
    let second = second_part.parse::<u32>().context("invalid second")?;
    if hour > 23 || minute > 59 || second > 60 {
        bail!("time out of range");
    }
    Ok((hour, minute, second))
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut y = i64::from(year);
    let m = i64::from(month);
    let d = i64::from(day);
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let month_prime = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * month_prime + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    y += if m <= 2 { 1 } else { 0 };
    (
        i32::try_from(y).unwrap_or(i32::MAX),
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

fn format_epoch_seconds(epoch_seconds: i64) -> String {
    let days = epoch_seconds.div_euclid(86_400);
    let seconds = epoch_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}
