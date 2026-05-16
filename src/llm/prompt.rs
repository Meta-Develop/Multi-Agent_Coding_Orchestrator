use crate::llm::{
    provider::{ProviderCapabilities, RequestBudget},
    transcript::{RedactionSummary, Redactor},
};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PromptContext {
    pub task: String,
    pub agent_id: String,
    pub claimed_paths: Vec<ClaimedPath>,
    pub repo_excerpts: Vec<RepoExcerpt>,
    pub validation_commands: Vec<ValidationCommand>,
    pub budget: RequestBudget,
    pub provider_capabilities: ProviderCapabilities,
}

impl PromptContext {
    pub fn new(task: impl Into<String>, agent_id: impl Into<String>) -> Self {
        Self {
            task: task.into(),
            agent_id: agent_id.into(),
            claimed_paths: Vec::new(),
            repo_excerpts: Vec::new(),
            validation_commands: Vec::new(),
            budget: RequestBudget::default(),
            provider_capabilities: ProviderCapabilities::local_fake(),
        }
    }

    pub fn with_claimed_path(
        mut self,
        path: impl Into<PathBuf>,
        reason: impl Into<String>,
    ) -> Self {
        self.claimed_paths.push(ClaimedPath {
            path: path.into(),
            reason: reason.into(),
        });
        self
    }

    pub fn with_repo_excerpt(mut self, excerpt: RepoExcerpt) -> Self {
        self.repo_excerpts.push(excerpt);
        self
    }

    pub fn with_validation_command(mut self, command: ValidationCommand) -> Self {
        self.validation_commands.push(command);
        self
    }

    pub fn assemble_prompt(&self, redactor: &Redactor) -> Prompt {
        let mut sections = Vec::new();
        let mut redactions = RedactionSummary::default();

        push_redacted_section(
            &mut sections,
            &mut redactions,
            redactor,
            "system",
            "You are a provider-neutral coding assistant. Return proposals, commands, and patches only; do not edit repository files directly.",
        );
        push_redacted_section(
            &mut sections,
            &mut redactions,
            redactor,
            "task",
            &format!("agent: {}\n{}", self.agent_id, self.task),
        );

        let mut claimed_paths = self.claimed_paths.clone();
        claimed_paths.sort_by(|left, right| left.path.cmp(&right.path));
        let claims_body = if claimed_paths.is_empty() {
            "none".to_string()
        } else {
            claimed_paths
                .iter()
                .map(|claim| format!("- {}: {}", claim.path.display(), claim.reason))
                .collect::<Vec<_>>()
                .join("\n")
        };
        push_redacted_section(
            &mut sections,
            &mut redactions,
            redactor,
            "claimed_paths",
            &claims_body,
        );

        let mut excerpts = self.repo_excerpts.clone();
        excerpts.sort_by(compare_excerpts);
        let excerpts_body = if excerpts.is_empty() {
            "none".to_string()
        } else {
            excerpts
                .iter()
                .map(render_excerpt)
                .collect::<Vec<_>>()
                .join("\n---\n")
        };
        push_redacted_section(
            &mut sections,
            &mut redactions,
            redactor,
            "repo_excerpts",
            &excerpts_body,
        );

        let validation_body = if self.validation_commands.is_empty() {
            "none".to_string()
        } else {
            self.validation_commands
                .iter()
                .map(render_validation_command)
                .collect::<Vec<_>>()
                .join("\n")
        };
        push_redacted_section(
            &mut sections,
            &mut redactions,
            redactor,
            "validation_commands",
            &validation_body,
        );

        let budget_body = format!(
            "max_input_chars: {}\nmax_output_chars: {}\nmax_total_tokens: {}\nprovider_max_context_tokens: {}\nprovider_max_output_tokens: {}\ncommands: {}\npatches: {}\ntranscripts: {}",
            self.budget.max_input_chars,
            self.budget.max_output_chars,
            self.budget.max_total_tokens,
            self.provider_capabilities.max_context_tokens,
            self.provider_capabilities.max_output_tokens,
            self.provider_capabilities.supports_command_proposals,
            self.provider_capabilities.supports_patch_proposals,
            self.provider_capabilities.supports_transcripts,
        );
        push_redacted_section(
            &mut sections,
            &mut redactions,
            redactor,
            "budgets_and_capabilities",
            &budget_body,
        );

        Prompt {
            sections,
            redactions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ClaimedPath {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RepoExcerpt {
    pub path: PathBuf,
    pub start_line: Option<usize>,
    pub end_line: Option<usize>,
    pub language: Option<String>,
    pub content: String,
}

impl RepoExcerpt {
    pub fn new(path: impl Into<PathBuf>, content: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            start_line: None,
            end_line: None,
            language: None,
            content: content.into(),
        }
    }

    pub fn with_lines(mut self, start_line: usize, end_line: usize) -> Self {
        self.start_line = Some(start_line);
        self.end_line = Some(end_line);
        self
    }

    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ValidationCommand {
    pub command: String,
    pub working_directory: Option<PathBuf>,
    pub required: bool,
}

impl ValidationCommand {
    pub fn required(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            working_directory: None,
            required: true,
        }
    }

    pub fn optional(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            working_directory: None,
            required: false,
        }
    }

    pub fn with_working_directory(mut self, working_directory: impl Into<PathBuf>) -> Self {
        self.working_directory = Some(working_directory.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Prompt {
    pub sections: Vec<PromptSection>,
    pub redactions: RedactionSummary,
}

impl Prompt {
    pub fn render(&self) -> String {
        self.sections
            .iter()
            .map(|section| format!("## {}\n{}", section.title, section.body))
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PromptSection {
    pub title: String,
    pub body: String,
}

fn push_redacted_section(
    sections: &mut Vec<PromptSection>,
    redactions: &mut RedactionSummary,
    redactor: &Redactor,
    title: &str,
    body: &str,
) {
    let redacted = redactor.redact(body);
    redactions.merge(redacted.summary);
    sections.push(PromptSection {
        title: title.to_string(),
        body: redacted.text,
    });
}

fn compare_excerpts(left: &RepoExcerpt, right: &RepoExcerpt) -> Ordering {
    left.path
        .cmp(&right.path)
        .then_with(|| left.start_line.cmp(&right.start_line))
        .then_with(|| left.end_line.cmp(&right.end_line))
}

fn render_excerpt(excerpt: &RepoExcerpt) -> String {
    let mut rendered = format!("path: {}", excerpt.path.display());
    if let Some(language) = &excerpt.language {
        rendered.push_str("\nlanguage: ");
        rendered.push_str(language);
    }
    if let Some(start_line) = excerpt.start_line {
        rendered.push_str("\nstart_line: ");
        rendered.push_str(&start_line.to_string());
    }
    if let Some(end_line) = excerpt.end_line {
        rendered.push_str("\nend_line: ");
        rendered.push_str(&end_line.to_string());
    }
    rendered.push_str("\ncontent:\n");
    rendered.push_str(&excerpt.content);
    rendered
}

fn render_validation_command(command: &ValidationCommand) -> String {
    let mut rendered = format!(
        "- {} [{}]",
        command.command,
        if command.required {
            "required"
        } else {
            "optional"
        }
    );
    if let Some(working_directory) = &command.working_directory {
        rendered.push_str(" cwd=");
        rendered.push_str(&working_directory.display().to_string());
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_assembly_uses_stable_section_and_path_ordering() {
        let context = PromptContext::new("Implement task", "agent-a")
            .with_claimed_path("src/z.rs", "later")
            .with_claimed_path("src/a.rs", "first")
            .with_repo_excerpt(RepoExcerpt::new("src/z.rs", "z").with_lines(10, 12))
            .with_repo_excerpt(RepoExcerpt::new("src/a.rs", "a").with_lines(1, 2))
            .with_validation_command(ValidationCommand::required("cargo test"));

        let prompt = context.assemble_prompt(&Redactor::new());

        let titles = prompt
            .sections
            .iter()
            .map(|section| section.title.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            titles,
            vec![
                "system",
                "task",
                "claimed_paths",
                "repo_excerpts",
                "validation_commands",
                "budgets_and_capabilities"
            ]
        );
        assert!(
            prompt.sections[2]
                .body
                .find("src/a.rs")
                .expect("src/a.rs present")
                < prompt.sections[2]
                    .body
                    .find("src/z.rs")
                    .expect("src/z.rs present")
        );
        assert!(
            prompt.sections[3]
                .body
                .find("src/a.rs")
                .expect("excerpt a present")
                < prompt.sections[3]
                    .body
                    .find("src/z.rs")
                    .expect("excerpt z present")
        );
    }
}
