//! Pure tests for the Vibe runtime adapter helpers.

use std::path::{Path, PathBuf};

use super::{
    config_document, export_directory, final_assistant_text, immutable_argument_template,
    parse_outcome, parse_usage, stop_message, validate_model, VibeUsage,
};

const MODEL_A: &str = "deepseek-v4-1-flash-1017";
const MODEL_B: &str = "zai-glm-5-3";

#[test]
fn vibe_operator_overrides_keep_only_the_binary() -> anyhow::Result<()> {
    use crate::runtime_adapter::{AdapterId, RuntimeAdapterConfig};

    let config = RuntimeAdapterConfig::try_from_adapter_environment_vars(
        AdapterId::Vibe,
        &[
            ("MACO_VIBE_BIN", "/operator/bin/vibe"),
            ("MACO_VIBE_ARGS", "--enabled-tools task --resume owner"),
            ("MACO_VIBE_ENV", "HOME,MISTRAL_API_KEY,VIBE_HOME"),
            ("MACO_VIBE_CWD_FLAG", "--add-dir"),
            ("MACO_VIBE_OUTPUT_CAPTURE", "stdout_and_stderr"),
            ("MACO_VIBE_STDIN_PROMPT", "true"),
        ],
    )?;
    let mut expected = RuntimeAdapterConfig::defaults_for(AdapterId::Vibe);
    expected.binary = Some(PathBuf::from("/operator/bin/vibe"));
    assert_eq!(config, expected);
    Ok(())
}

#[test]
fn vibe_render_binds_two_models_and_refuses_contract_mutation() -> anyhow::Result<()> {
    use crate::runtime_adapter::{LaunchContext, RuntimeAdapterConfig, RuntimeId};

    for model in [MODEL_A, MODEL_B] {
        let config = RuntimeAdapterConfig::defaults(RuntimeId::Vibe);
        let context = LaunchContext {
            prompt: Path::new("/private/prompt.md"),
            model: Some(model),
            effort: Some("high"),
            cwd: Path::new("/workspace"),
            output: Path::new("/private/last-message.raw"),
        };
        let launch = config.render(&context)?;
        for pair in [
            ["--model", model],
            ["--workdir", "/workspace"],
            ["--prompt-file", "/private/prompt.md"],
            ["--output-dir", "/private/last-message.raw.vibe-export"],
        ] {
            assert!(launch.argv.windows(2).any(|window| window == pair));
        }
        assert!(!launch.argv.iter().any(|arg| arg == "high"));
        assert!(launch.env.is_empty());

        let mut changed = config.clone();
        changed.argument_template.push("--resume".into());
        assert!(changed.vibe_launch_contract(&context).is_err());
        let mut changed = config.clone();
        changed.env_passthrough.push("MISTRAL_API_KEY".into());
        assert!(changed.vibe_launch_contract(&context).is_err());
        let mut changed = config.clone();
        changed.feed_prompt_on_stdin = true;
        assert!(changed.vibe_launch_contract(&context).is_err());

        // A real existing executable reaches the guard without being spawned.
        let mut uncontained = config;
        uncontained.binary = Some(PathBuf::from("/bin/sh"));
        let error = uncontained
            .execute(&context)
            .expect_err("Vibe needs containment");
        assert!(error.to_string().contains("uncontained Vibe"));
    }
    Ok(())
}

fn vibe_export(usage: &str) -> Vec<u8> {
    format!(r#"{{"usage":{usage},"cost_usd":0.0,"session_id":"s-1","model":"{MODEL_A}"}}"#)
        .into_bytes()
}

fn vibe_stream(lines: &[&str]) -> Vec<u8> {
    let mut stream = String::new();
    for line in lines {
        stream.push_str(line);
        stream.push('\n');
    }
    stream.into_bytes()
}

#[test]
fn vibe_argument_template_is_exact_and_repeats_enabled_tools() {
    let template = immutable_argument_template();
    assert_eq!(
        template,
        vec![
            "--workdir",
            "{cwd}",
            "--trust",
            "--model",
            "{model}",
            "--agent",
            "auto-approve",
            "--auto-approve",
            "--enabled-tools",
            "bash",
            "--enabled-tools",
            "read_file",
            "--enabled-tools",
            "write_file",
            "--enabled-tools",
            "edit",
            "--max-turns",
            "200",
            "--max-tokens",
            "10000000",
            "--time-limit",
            "3600",
            "--output",
            "streaming",
            "--output-dir",
            "{vibe_output_dir}",
            "--prompt-file",
            "{prompt}",
        ]
    );
    let enabled_tools = template
        .iter()
        .filter(|argument| argument.as_str() == "--enabled-tools")
        .count();
    assert_eq!(enabled_tools, 4);

    let mut worker: Vec<std::ffi::OsString> = template.iter().map(Into::into).collect();
    super::journaled_worker_arguments(&mut worker);
    let tools: Vec<_> = worker
        .windows(2)
        .filter(|pair| pair[0] == "--enabled-tools")
        .map(|pair| pair[1].to_str().unwrap())
        .collect();
    assert_eq!(tools, ["bash", "read_file"]);
    let mut expected: Vec<std::ffi::OsString> = template.iter().map(Into::into).collect();
    expected.drain(12..16);
    assert_eq!(worker, expected);
}

#[test]
fn vibe_journaled_config_encodes_the_per_attempt_shell_as_data() {
    let shell = Path::new("/private/attempt 'quoted' \\\"/journal-shell");
    let config = super::journaled_config_document(MODEL_A, shell).unwrap();
    let base = config_document(MODEL_A).unwrap();
    let table_prefix = format!(
        "\n[tools.bash]\ndefault_timeout = {}\nmax_timeout_seconds = {}\nshell = ",
        super::JOURNALED_BASH_DEFAULT_TIMEOUT_SECONDS,
        super::JOURNALED_BASH_MAX_TIMEOUT_SECONDS
    );
    assert_eq!(
        config
            .matches(&format!(
                "default_timeout = {}",
                super::JOURNALED_BASH_DEFAULT_TIMEOUT_SECONDS
            ))
            .count(),
        1
    );
    assert_eq!(
        config
            .matches(&format!(
                "max_timeout_seconds = {}",
                super::JOURNALED_BASH_MAX_TIMEOUT_SECONDS
            ))
            .count(),
        1
    );
    let encoded = config
        .strip_prefix(&base)
        .unwrap()
        .strip_prefix(&table_prefix)
        .unwrap()
        .trim_end();
    // The generated TOML basic string uses the JSON string escape subset.
    let decoded: String = serde_json::from_str(encoded).unwrap();
    assert_eq!(decoded, shell.to_str().unwrap());
}

#[test]
fn vibe_export_directory_appends_suffix_and_keeps_parent() {
    assert_eq!(
        export_directory(Path::new("/tmp/run/output")),
        PathBuf::from("/tmp/run/output.vibe-export")
    );
    assert_eq!(
        export_directory(Path::new("output")),
        PathBuf::from("output.vibe-export")
    );
    assert_eq!(
        export_directory(Path::new("/tmp/run/output")).parent(),
        Some(Path::new("/tmp/run"))
    );
}

#[test]
fn vibe_validate_model_accepts_provider_ids() {
    assert_eq!(validate_model(Some(MODEL_A)).unwrap(), MODEL_A);
    assert_eq!(validate_model(Some(MODEL_B)).unwrap(), MODEL_B);
    assert_eq!(
        validate_model(Some("mistral/mistral-large-2411")).unwrap(),
        "mistral/mistral-large-2411"
    );
}

#[test]
fn vibe_validate_model_rejects_missing_empty_and_oversized_ids() {
    assert!(validate_model(None).is_err());
    assert!(validate_model(Some("")).is_err());
    let oversized = "a".repeat(257);
    assert!(validate_model(Some(&oversized)).is_err());
    let bounded = "a".repeat(256);
    assert!(validate_model(Some(&bounded)).is_ok());
}

#[test]
fn vibe_validate_model_rejects_injection_and_traversal() {
    for model in [
        "deepseek v4",
        "model;rm -rf /",
        "model\n--trust",
        "model$(id)",
        "model`id`",
        "../etc/passwd",
        "mistral/../../secret",
        "..",
        "model*",
        "model.*",
        "^model",
        "model|cat",
        "model\"quoted",
        "model'quoted",
        "/absolute/model",
        "trailing/",
        ".hidden",
    ] {
        assert!(
            validate_model(Some(model)).is_err(),
            "expected rejection for {model:?}"
        );
    }
}

#[test]
fn vibe_config_document_pins_model_and_disables_subsystems() {
    let document = config_document(MODEL_A).unwrap();
    assert!(document.contains(&format!("active_model = \"{MODEL_A}\"")));
    assert!(document.contains(&format!("allowed_models = [\"{MODEL_A}\"]")));
    for flag in [
        "enable_subagents = false",
        "enable_mcp = false",
        "enable_connectors = false",
        "enable_telemetry = false",
        "enable_otel = false",
        "enable_update_checks = false",
        "enable_auto_update = false",
        "enable_background_processes = false",
        "mcp_servers = []",
        "connectors = []",
        "generate_titles = false",
        "title = \"active\"",
        "smart_approve = \"active\"",
    ] {
        assert!(document.contains(flag), "missing {flag}");
    }
    assert!(document.contains(&format!("name = \"{MODEL_A}\"")));
    assert!(document.contains(&format!("alias = \"{MODEL_A}\"")));
    assert!(document.contains("provider = \"mistral\""));
    assert!(!document.contains("api_key"));
    assert!(!document.contains("cost"));
}

#[test]
fn vibe_config_document_differs_per_model_and_rejects_injection() {
    let first = config_document(MODEL_A).unwrap();
    let second = config_document(MODEL_B).unwrap();
    assert_ne!(first, second);
    assert!(second.contains(&format!("active_model = \"{MODEL_B}\"")));
    assert!(!second.contains(MODEL_A));
    assert!(config_document("model\"\nactive_model = \"evil").is_err());
    assert!(config_document("").is_err());
}

#[test]
fn vibe_parse_usage_reads_all_four_counters() {
    let bytes = vibe_export(
        r#"{"input_tokens":1200,"output_tokens":300,"cached_input_tokens":200,"total_tokens":1500}"#,
    );
    let usage = parse_usage(&bytes).unwrap();
    assert_eq!(
        usage,
        VibeUsage {
            input_tokens: 1200,
            output_tokens: 300,
            cached_input_tokens: 200,
            total_tokens: 1500,
        }
    );
}

#[test]
fn vibe_parse_usage_treats_cached_as_subset_not_additive() {
    let bytes = vibe_export(
        r#"{"input_tokens":1000,"output_tokens":500,"cached_input_tokens":1000,"total_tokens":1500}"#,
    );
    let usage = parse_usage(&bytes).unwrap();
    assert_eq!(usage.total_tokens, 1500);
    assert_eq!(usage.cached_input_tokens, 1000);
    assert_ne!(
        usage.total_tokens,
        usage.input_tokens + usage.cached_input_tokens
    );
}

#[test]
fn vibe_parse_usage_ignores_zero_and_nonzero_cost() {
    let zero = vibe_export(
        r#"{"input_tokens":10,"output_tokens":5,"cached_input_tokens":0,"total_tokens":15}"#,
    );
    let nonzero = br#"{"usage":{"input_tokens":10,"output_tokens":5,"cached_input_tokens":0,"total_tokens":15},"cost_usd":9.99}"#;
    assert_eq!(parse_usage(&zero).unwrap(), parse_usage(nonzero).unwrap());
}

#[test]
fn vibe_parse_usage_rejects_missing_malformed_and_inconsistent_blocks() {
    assert!(parse_usage(b"").is_err());
    assert!(parse_usage(b"{}").is_err());
    assert!(parse_usage(b"not json").is_err());
    assert!(parse_usage(br#"{"usage":null}"#).is_err());
    assert!(parse_usage(br#"{"usage":{}}"#).is_err());
    assert!(parse_usage(
        br#"{"usage":{"input_tokens":1,"output_tokens":1,"cached_input_tokens":0}}"#
    )
    .is_err());
    assert!(parse_usage(
        br#"{"usage":{"input_tokens":-1,"output_tokens":1,"cached_input_tokens":0,"total_tokens":0}}"#
    )
    .is_err());
    assert!(parse_usage(
        br#"{"usage":{"input_tokens":"1","output_tokens":1,"cached_input_tokens":0,"total_tokens":2}}"#
    )
    .is_err());
    // cached exceeds input
    assert!(parse_usage(
        br#"{"usage":{"input_tokens":10,"output_tokens":5,"cached_input_tokens":11,"total_tokens":15}}"#
    )
    .is_err());
    // total does not equal input + output
    assert!(parse_usage(
        br#"{"usage":{"input_tokens":10,"output_tokens":5,"cached_input_tokens":0,"total_tokens":16}}"#
    )
    .is_err());
    // Typed deserialization rejects ambiguous duplicate usage keys.
    let duplicate = br#"{"usage":{"input_tokens":10,"output_tokens":5,"cached_input_tokens":0,"total_tokens":15},"usage":{"input_tokens":1,"output_tokens":1,"cached_input_tokens":0,"total_tokens":2}}"#;
    assert!(parse_usage(duplicate).is_err());
}

#[test]
fn vibe_parse_usage_rejects_oversized_export() {
    let mut bytes = vibe_export(
        r#"{"input_tokens":1,"output_tokens":1,"cached_input_tokens":0,"total_tokens":2}"#,
    );
    bytes.resize(4 * 1024 * 1024 + 1, b' ');
    assert!(parse_usage(&bytes).is_err());
}

#[test]
fn vibe_final_assistant_text_returns_last_completed_message() {
    let stream = vibe_stream(&[
        r#"{"type":"message","role":"user","content":[{"type":"text","text":"do the thing"}]}"#,
        r#"{"type":"reasoning","text":"thinking"}"#,
        r#"{"type":"message","role":"assistant","generationStatus":"completed","content":[{"type":"text","text":"first answer"}]}"#,
        r#"{"type":"tool_call","name":"bash","arguments":{"command":"ls"}}"#,
        r#"{"type":"effect","kind":"file_write","path":"out.txt"}"#,
        r#"{"type":"message","role":"assistant","generationStatus":"completed","content":[{"type":"text","text":"final part one"},{"type":"text","text":"final part two"}]}"#,
    ]);
    assert_eq!(
        final_assistant_text(&stream).unwrap(),
        "final part one\n\nfinal part two"
    );
}

#[test]
fn vibe_final_assistant_text_skips_discarded_and_incomplete_messages() {
    let stream = vibe_stream(&[
        r#"{"type":"message","role":"assistant","generationStatus":"completed","content":[{"type":"text","text":"kept"}]}"#,
        r#"{"type":"message","role":"assistant","generationStatus":"completed","outcome":{"type":"discarded"},"content":[{"type":"text","text":"discarded"}]}"#,
        r#"{"type":"message","role":"assistant","generationStatus":"streaming","content":[{"type":"text","text":"partial"}]}"#,
        r#"{"type":"message","role":"user","content":[{"type":"text","text":"later user"}]}"#,
    ]);
    assert_eq!(final_assistant_text(&stream).unwrap(), "kept");
}

#[test]
fn vibe_final_assistant_text_ignores_non_text_blocks() {
    let stream = vibe_stream(&[
        r#"{"type":"message","role":"assistant","generationStatus":"completed","content":[{"type":"reasoning","text":"hidden"},{"type":"text","text":"visible"}]}"#,
    ]);
    assert_eq!(final_assistant_text(&stream).unwrap(), "visible");
}

#[test]
fn vibe_final_assistant_text_rejects_malformed_and_truncated_streams() {
    assert!(final_assistant_text(b"").is_err());
    assert!(final_assistant_text(b"{\"type\":\"message\"}").is_err());
    let truncated = vibe_stream(&[
        r#"{"type":"message","role":"assistant","generationStatus":"completed","content":[{"type":"text","text":"answer"}]}"#,
    ]);
    let mut cut = truncated.clone();
    cut.pop();
    assert!(final_assistant_text(&cut).is_err());
    let malformed = vibe_stream(&[
        r#"{"type":"message","role":"assistant","generationStatus":"completed","content":[{"type":"text","text":"answer"}]}"#,
        "not json",
    ]);
    assert!(final_assistant_text(&malformed).is_err());
    let no_assistant = vibe_stream(&[
        r#"{"type":"message","role":"user","content":[{"type":"text","text":"hi"}]}"#,
    ]);
    assert!(final_assistant_text(&no_assistant).is_err());
}

#[test]
fn vibe_final_assistant_text_rejects_oversized_stream_and_text() {
    let mut oversized = vibe_stream(&[
        r#"{"type":"message","role":"assistant","generationStatus":"completed","content":[{"type":"text","text":"answer"}]}"#,
    ]);
    oversized.resize(8 * 1024 * 1024 + 1, b' ');
    assert!(final_assistant_text(&oversized).is_err());

    let long_text = "x".repeat(256 * 1024 + 1);
    let line = format!(
        r#"{{"type":"message","role":"assistant","generationStatus":"completed","content":[{{"type":"text","text":"{long_text}"}}]}}"#
    );
    assert!(final_assistant_text(&vibe_stream(&[line.as_str()])).is_err());
}

#[test]
fn vibe_final_assistant_text_byte_boundary() {
    const CAP: usize = 256 * 1024;
    // A single text block whose UTF-8 encoding is exactly the cap: the multibyte
    // character straddles the boundary, so a byte-wise truncation would split it.
    let mut single = "x".repeat(CAP - 'é'.len_utf8());
    single.push('é');
    assert_eq!(single.len(), CAP);
    let single_line = serde_json::json!({
        "type": "message",
        "role": "assistant",
        "generationStatus": "completed",
        "content": [{"type": "text", "text": single}],
    })
    .to_string();
    let stream = vibe_stream(&[single_line.as_str()]);
    assert!(stream.len() <= 8 * 1024 * 1024);
    assert_eq!(final_assistant_text(&stream).unwrap(), single);

    // Two text blocks whose joined output, including the two-newline separator,
    // is exactly the cap.
    let first = "a".repeat(CAP / 2 - 1);
    let second = format!("{}é", "b".repeat(CAP - first.len() - 2 - 'é'.len_utf8()));
    assert_eq!(first.len() + 2 + second.len(), CAP);
    let joined = format!("{first}\n\n{second}");
    assert_eq!(joined.len(), CAP);
    let two_line = serde_json::json!({
        "type": "message",
        "role": "assistant",
        "generationStatus": "completed",
        "content": [
            {"type": "text", "text": first},
            {"type": "text", "text": second},
        ],
    })
    .to_string();
    let stream = vibe_stream(&[two_line.as_str()]);
    assert!(stream.len() <= 8 * 1024 * 1024);
    assert_eq!(final_assistant_text(&stream).unwrap(), joined);

    // One complete multibyte character past the joined-text cap is rejected.
    // The overflow stays in the second block so the two-block aggregation path,
    // including the two-newline separator, is what crosses the cap.
    let over_second = format!("{second}é");
    assert_eq!(over_second.len(), second.len() + 'é'.len_utf8());
    let over_joined = format!("{first}\n\n{over_second}");
    assert_eq!(over_joined.len(), CAP + 'é'.len_utf8());
    let over_line = serde_json::json!({
        "type": "message",
        "role": "assistant",
        "generationStatus": "completed",
        "content": [
            {"type": "text", "text": first},
            {"type": "text", "text": over_second},
        ],
    })
    .to_string();
    let stream = vibe_stream(&[over_line.as_str()]);
    assert!(stream.len() <= 8 * 1024 * 1024);
    assert!(final_assistant_text(&stream).is_err());
}

fn vibe_export_with_outcome(usage: &str, outcome: &str) -> Vec<u8> {
    format!(r#"{{"usage":{usage},"outcome":{outcome}}}"#).into_bytes()
}

#[test]
fn vibe_parse_outcome_reads_the_top_level_outcome_string() {
    let bytes = vibe_export_with_outcome(
        r#"{"input_tokens":10,"output_tokens":5,"cached_input_tokens":0,"total_tokens":15}"#,
        "\"token_limit\"",
    );
    assert_eq!(parse_outcome(&bytes).as_deref(), Some("token_limit"));
}

#[test]
fn vibe_parse_outcome_rejects_missing_nonstring_invalid_and_oversized_values() {
    let usage =
        r#"{"input_tokens":10,"output_tokens":5,"cached_input_tokens":0,"total_tokens":15}"#;
    // Missing outcome.
    assert_eq!(
        parse_outcome(vibe_export(usage).as_slice()),
        None,
        "missing outcome"
    );
    // Non-string outcome.
    assert_eq!(
        parse_outcome(vibe_export_with_outcome(usage, "3").as_slice()),
        None,
        "non-string outcome"
    );
    // Uppercase letters.
    assert_eq!(
        parse_outcome(vibe_export_with_outcome(usage, "\"Token_Limit\"").as_slice()),
        None,
        "uppercase outcome"
    );
    // Spaces.
    assert_eq!(
        parse_outcome(vibe_export_with_outcome(usage, "\"token limit\"").as_slice()),
        None,
        "outcome with a space"
    );
    // Oversized document.
    let mut oversized = vibe_export_with_outcome(usage, "\"token_limit\"");
    oversized.resize(4 * 1024 * 1024 + 1, b' ');
    assert_eq!(parse_outcome(&oversized), None, "oversized document");
}

#[test]
fn vibe_stop_message_names_each_limit_outcome_with_the_template_numbers() {
    let template = immutable_argument_template();
    let value = |flag: &str| {
        template
            .iter()
            .position(|argument| argument == flag)
            .map(|index| template[index + 1].clone())
            .unwrap()
    };
    let expected = |outcome: &str| {
        format!(
            "Vibe stopped without finishing: run outcome {outcome}; MACO launches Vibe with --max-turns {}, --max-tokens {} and --time-limit {}",
            value("--max-turns"),
            value("--max-tokens"),
            value("--time-limit")
        )
    };
    for outcome in [
        "turn_limit",
        "token_limit",
        "price_limit",
        "deadline",
        "terminated",
        "length",
        "refusal",
    ] {
        assert_eq!(
            stop_message(outcome).as_deref(),
            Some(expected(outcome).as_str())
        );
    }
    // The template numbers are the documented launch limits.
    assert_eq!(value("--max-turns"), "200");
    assert_eq!(value("--max-tokens"), "10000000");
    assert_eq!(value("--time-limit"), "3600");
}

#[test]
fn vibe_stop_message_returns_none_for_other_outcomes() {
    assert_eq!(stop_message("finished"), None);
    assert_eq!(stop_message("aborted"), None);
}
