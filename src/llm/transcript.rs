use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Transcript {
    pub turns: Vec<TranscriptTurn>,
}

impl Transcript {
    pub fn new() -> Self {
        Self { turns: Vec::new() }
    }

    pub fn with_turn(mut self, role: TurnRole, content: impl Into<String>) -> Self {
        self.turns.push(TranscriptTurn {
            role,
            content: content.into(),
        });
        self
    }

    pub fn push(&mut self, role: TurnRole, content: impl Into<String>) {
        self.turns.push(TranscriptTurn {
            role,
            content: content.into(),
        });
    }

    pub fn redacted(&self, redactor: &Redactor) -> (Self, RedactionSummary) {
        let mut summary = RedactionSummary::default();
        let turns = self
            .turns
            .iter()
            .map(|turn| {
                let redacted = redactor.redact(&turn.content);
                summary.merge(redacted.summary);
                TranscriptTurn {
                    role: turn.role,
                    content: redacted.text,
                }
            })
            .collect();

        (Self { turns }, summary)
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TranscriptTurn {
    pub role: TurnRole,
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Redactor {
    rules: Vec<RedactionRule>,
    redact_secret_assignments: bool,
}

impl Redactor {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            redact_secret_assignments: true,
        }
    }

    pub fn without_secret_assignment_detection(mut self) -> Self {
        self.redact_secret_assignments = false;
        self
    }

    pub fn with_private_value(
        mut self,
        label: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        let label = label.into();
        let value = value.into();
        if !label.trim().is_empty()
            && !value.is_empty()
            && !self.rules.iter().any(|rule| rule.value == value)
        {
            self.rules.push(RedactionRule { label, value });
            self.rules.sort_by(|left, right| {
                right
                    .value
                    .len()
                    .cmp(&left.value.len())
                    .then_with(|| left.value.cmp(&right.value))
                    .then_with(|| left.label.cmp(&right.label))
            });
        }
        self
    }

    pub fn redact(&self, input: &str) -> RedactedText {
        let mut text = if self.redact_secret_assignments {
            redact_secret_assignments(input)
        } else {
            RedactedText {
                text: input.to_string(),
                summary: RedactionSummary::default(),
            }
        };

        for rule in &self.rules {
            let replacement = format!("<redacted:{}>", rule.label);
            let occurrences = count_occurrences(&text.text, &rule.value);
            if occurrences == 0 {
                continue;
            }
            text.text = text.text.replace(&rule.value, &replacement);
            text.summary.record(&rule.label, occurrences);
        }

        text
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Redactor")
            .field(
                "rules",
                &self
                    .rules
                    .iter()
                    .map(|rule| format!("<redacted:{}>", rule.label))
                    .collect::<Vec<_>>(),
            )
            .field("redact_secret_assignments", &self.redact_secret_assignments)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RedactionRule {
    pub label: String,
    pub value: String,
}

impl std::fmt::Debug for RedactionRule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedactionRule")
            .field("label", &self.label)
            .field("value", &format!("<redacted:{}>", self.label))
            .finish()
    }
}

impl Drop for RedactionRule {
    fn drop(&mut self) {
        zeroize_string(&mut self.value);
    }
}

fn zeroize_string(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    bytes.fill(0);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    bytes.clear();
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct RedactionSummary {
    pub total_replacements: usize,
    pub by_label: BTreeMap<String, usize>,
}

impl RedactionSummary {
    pub fn record(&mut self, label: &str, count: usize) {
        if count == 0 {
            return;
        }
        self.total_replacements = self.total_replacements.saturating_add(count);
        self.by_label
            .entry(label.to_string())
            .and_modify(|existing| *existing = existing.saturating_add(count))
            .or_insert(count);
    }

    pub fn merge(&mut self, other: RedactionSummary) {
        self.total_replacements = self
            .total_replacements
            .saturating_add(other.total_replacements);
        for (label, count) in other.by_label {
            self.by_label
                .entry(label)
                .and_modify(|existing| *existing = existing.saturating_add(count))
                .or_insert(count);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RedactedText {
    pub text: String,
    pub summary: RedactionSummary,
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }

    haystack.match_indices(needle).count()
}

fn redact_secret_assignments(input: &str) -> RedactedText {
    let mut summary = RedactionSummary::default();
    let mut output = String::with_capacity(input.len());

    for line in input.split_inclusive('\n') {
        let (body, newline) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };

        let redacted = redact_secret_assignment_line(body);
        if redacted.changed {
            summary.record("secret", 1);
        }
        output.push_str(&redacted.text);
        output.push_str(newline);
    }

    if input.is_empty() {
        return RedactedText {
            text: String::new(),
            summary,
        };
    }

    RedactedText {
        text: output,
        summary,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LineRedaction {
    text: String,
    changed: bool,
}

fn redact_secret_assignment_line(line: &str) -> LineRedaction {
    let mut search_from = 0;
    while search_from < line.len() {
        let Some((relative_index, delimiter)) = find_assignment_delimiter(&line[search_from..])
        else {
            break;
        };
        let delimiter_index = search_from + relative_index;
        let value_start = delimiter_index + delimiter.len();
        let key = trailing_assignment_key(&line[..delimiter_index]);
        if is_secret_key(key) {
            let value = &line[value_start..];
            if !value.trim().is_empty() {
                let leading_ws_len = value.len().saturating_sub(value.trim_start().len());
                let prefix = &line[..value_start];
                let leading_ws = &value[..leading_ws_len];
                return LineRedaction {
                    text: format!("{prefix}{leading_ws}<redacted:secret>"),
                    changed: true,
                };
            }
        }
        if delimiter.is_empty() {
            break;
        }
        search_from = value_start;
    }

    LineRedaction {
        text: line.to_string(),
        changed: false,
    }
}

fn find_assignment_delimiter(line: &str) -> Option<(usize, &'static str)> {
    let equals = line.find('=');
    let colon = line.find(':');

    match (equals, colon) {
        (Some(eq), Some(col)) if eq < col => Some((eq, "=")),
        (Some(_), Some(col)) => Some((col, ":")),
        (Some(eq), None) => Some((eq, "=")),
        (None, Some(col)) => Some((col, ":")),
        (None, None) => None,
    }
}

fn trailing_assignment_key(prefix: &str) -> &str {
    let trimmed = prefix.trim_end();
    let start = trimmed
        .rfind(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '"' | '\''))
        })
        .map(|index| {
            index
                + trimmed[index..]
                    .chars()
                    .next()
                    .map(char::len_utf8)
                    .unwrap_or(1)
        })
        .unwrap_or(0);
    &trimmed[start..]
}

fn is_secret_key(key: &str) -> bool {
    let normalized = key
        .trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace())
        .to_ascii_uppercase()
        .replace('-', "_");

    normalized.contains("SECRET")
        || normalized.contains("TOKEN")
        || normalized.contains("PASSWORD")
        || normalized.contains("PRIVATE_KEY")
        || normalized.contains("API_KEY")
        || normalized.contains("AUTHORIZATION")
        || normalized.contains("BEARER")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_literal_values_and_secret_assignments() {
        let redactor = Redactor::new().with_private_value("repo", "/private/repo");

        let redacted = redactor
            .redact("path=/private/repo\nAPI_TOKEN=abc123\nnormal=value\npassword: hunter2\n");

        assert_eq!(
            redacted.text,
            "path=<redacted:repo>\nAPI_TOKEN=<redacted:secret>\nnormal=value\npassword: <redacted:secret>\n"
        );
        assert_eq!(redacted.summary.total_replacements, 3);
        assert_eq!(redacted.summary.by_label.get("repo"), Some(&1));
        assert_eq!(redacted.summary.by_label.get("secret"), Some(&2));
    }

    #[test]
    fn redacts_overlapping_private_values_longest_first_and_deduplicates() {
        let redactor = Redactor::new()
            .with_private_value("short", "abc")
            .with_private_value("long", "abcdef")
            .with_private_value("duplicate", "abcdef")
            .with_private_value("empty", "");

        let redacted = redactor.redact("values abcdef and abc");

        assert_eq!(redacted.text, "values <redacted:long> and <redacted:short>");
        assert_eq!(redacted.summary.total_replacements, 2);
        assert_eq!(redacted.summary.by_label.get("long"), Some(&1));
        assert_eq!(redacted.summary.by_label.get("short"), Some(&1));
        assert!(!redacted.text.contains("def"));
    }

    #[test]
    fn transcript_redaction_preserves_roles_and_order() {
        let transcript = Transcript::new()
            .with_turn(TurnRole::User, "token=abc")
            .with_turn(TurnRole::Assistant, "ok");

        let (redacted, summary) = transcript.redacted(&Redactor::new());

        assert_eq!(redacted.turns[0].role, TurnRole::User);
        assert_eq!(redacted.turns[0].content, "token=<redacted:secret>");
        assert_eq!(redacted.turns[1].role, TurnRole::Assistant);
        assert_eq!(summary.total_replacements, 1);
    }

    #[test]
    fn redacts_secret_assignments_after_the_first_delimiter_on_a_line() {
        let redactor = Redactor::new();

        let json = redactor.redact(r#"{"user":"a","api_key":"sk-test123"}"#);
        assert_eq!(json.text, r#"{"user":"a","api_key":<redacted:secret>"#);
        assert_eq!(json.summary.by_label.get("secret"), Some(&1));

        let env = redactor.redact("env: API_TOKEN=abc");
        assert_eq!(env.text, "env: API_TOKEN=<redacted:secret>");

        let curl = redactor.redact("cmd=curl -H 'X-Api-Key: v'");
        assert_eq!(curl.text, "cmd=curl -H 'X-Api-Key: <redacted:secret>");

        let header = redactor.redact("Authorization: Bearer tok");
        assert_eq!(header.text, "Authorization: <redacted:secret>");

        let bearer = redactor.redact("proxy-authorization: Bearer tok");
        assert_eq!(bearer.text, "proxy-authorization: <redacted:secret>");

        let unchanged = redactor.redact(r#"{"user":"a","name":"visible"}"#);
        assert_eq!(unchanged.text, r#"{"user":"a","name":"visible"}"#);
        assert_eq!(unchanged.summary.total_replacements, 0);
    }

    #[test]
    fn redactor_debug_and_error_formatting_omit_private_values() {
        let placeholder = "placeholder.lifecycle.test-value.v1";
        let redactor = Redactor::new().with_private_value("fixture", placeholder);
        let debug = format!("{redactor:?}");
        let display = format!("{redactor:?}");
        let error_text = format!("redactor failed: {redactor:?}");

        assert!(!debug.contains(placeholder));
        assert!(!display.contains(placeholder));
        assert!(!error_text.contains(placeholder));
        assert!(debug.contains("<redacted:fixture>"));

        let rule = RedactionRule {
            label: "fixture".to_string(),
            value: placeholder.to_string(),
        };
        let rule_debug = format!("{rule:?}");
        assert!(!rule_debug.contains(placeholder));
        assert!(rule_debug.contains("<redacted:fixture>"));
    }
}
