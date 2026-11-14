//! Operator-configured decision-model provider adapter (#829, #970).
//!
//! This is the only module that performs I/O for decision proposals: the
//! deterministic selector never calls it, and the built-in adapter speaks
//! plain HTTP to a self-hosted endpoint only.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::selection::decision_proposal::{
    adopt_decision_proposal, DecisionAdoption, DecisionAdoptionOutcome, DecisionOptionProbability,
    DecisionProposal, DecisionQuestion,
};

pub const SYSTEMONE_PATH: &str = "/v1/systemone";
pub const SYSTEMONE_QUESTION_ID: &str = "binding";
pub const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

const INSTRUCTIONS: &str = "Which admitted runtime/model/reasoning-effort binding should perform this task with the lowest total cost of an accepted result? Each option states its dated prior, posterior quality, expected cost per accepted task and quota state.";

/// Operator-held provider configuration; nothing constructs it by default, so
/// the provider stays disabled until a caller holds one of these.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionProviderConfig {
    pub endpoint: String,
    pub model: String,
    pub threshold_basis_points: u16,
    pub timeout_ms: u64,
}

pub fn systemone_request(question: &DecisionQuestion, model: &str) -> serde_json::Value {
    let task_profile = serde_json::to_value(&question.task).unwrap_or(serde_json::Value::Null);
    let criteria = question
        .options
        .iter()
        .map(|option| {
            (
                option.option_id.clone(),
                serde_json::Value::String(option.description.clone()),
            )
        })
        .collect::<serde_json::Map<String, serde_json::Value>>();
    serde_json::json!({
        "model": model,
        "state": {
            "task": question.task_text,
            "task_profile": task_profile,
        },
        "questions": {
            SYSTEMONE_QUESTION_ID: {
                "type": "choice",
                "instructions": INSTRUCTIONS,
                "criteria": criteria,
            },
        },
    })
}

pub fn parse_systemone_response(
    question: &DecisionQuestion,
    requested_model: &str,
    body: &[u8],
) -> Result<DecisionProposal, String> {
    let root: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "response is not a JSON object".to_string())?;
    let root = root
        .as_object()
        .ok_or_else(|| "response is not a JSON object".to_string())?;
    let served_model = root
        .get("model")
        .and_then(|value| value.as_str())
        .filter(|model| !model.is_empty())
        .ok_or_else(|| "response has no served model".to_string())?;
    let answer = root
        .get("answers")
        .and_then(|answers| answers.get(SYSTEMONE_QUESTION_ID))
        .and_then(|answer| answer.as_object())
        .ok_or_else(|| "response has no choice answer for binding".to_string())?;
    if answer.get("type").and_then(|value| value.as_str()) != Some("choice") {
        return Err("response has no choice answer for binding".to_string());
    }
    let probabilities = answer
        .get("probabilities")
        .and_then(|value| value.as_object())
        .ok_or_else(|| "response has no probabilities object".to_string())?;
    for (key, value) in probabilities {
        let probability = value
            .as_f64()
            .filter(|p| p.is_finite() && (0.0..=1.0).contains(p));
        if probability.is_none() {
            return Err(format!("probability for {key} is not between 0 and 1"));
        }
    }
    let basis_points = |value: &serde_json::Value| -> u16 {
        ((value.as_f64().unwrap_or(0.0) * 10000.0).round()) as u16
    };
    let mut entries = Vec::new();
    for option in &question.options {
        if let Some(value) = probabilities.get(&option.option_id) {
            entries.push(DecisionOptionProbability {
                option_id: option.option_id.clone(),
                probability_basis_points: basis_points(value),
            });
        }
    }
    for (key, value) in probabilities {
        if question
            .options
            .iter()
            .any(|option| option.option_id == *key)
        {
            continue;
        }
        entries.push(DecisionOptionProbability {
            option_id: key.clone(),
            probability_basis_points: basis_points(value),
        });
    }
    Ok(DecisionProposal {
        decision_model: requested_model.to_string(),
        decision_model_version: served_model.to_string(),
        probabilities: entries,
    })
}

fn find_crlf(bytes: &[u8], from: usize) -> Option<usize> {
    let mut index = from;
    while index + 1 < bytes.len() {
        if bytes[index] == b'\r' && bytes[index + 1] == b'\n' {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    let mut position = 0usize;
    loop {
        let line_end = find_crlf(body, position).ok_or("truncated HTTP response")?;
        let line = std::str::from_utf8(&body[position..line_end])
            .map_err(|_| "malformed HTTP response".to_string())?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| "malformed HTTP response".to_string())?;
        position = line_end + 2;
        if size == 0 {
            break;
        }
        if position + size + 2 > body.len() {
            return Err("truncated HTTP response".to_string());
        }
        if body[position + size] != b'\r' || body[position + size + 1] != b'\n' {
            return Err("malformed HTTP response".to_string());
        }
        decoded.extend_from_slice(&body[position..position + size]);
        position += size + 2;
    }
    Ok(decoded)
}

pub fn post_systemone(endpoint: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let url =
        Url::parse(endpoint).map_err(|_| "unsupported endpoint: does not parse".to_string())?;
    if url.scheme() != "http" {
        return Err(format!(
            "unsupported endpoint: scheme {} is not http",
            url.scheme()
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("unsupported endpoint: credentials are not allowed".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("unsupported endpoint: query or fragment is not allowed".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "unsupported endpoint: no host".to_string())?
        .to_string();
    if url.path() != "/" {
        return Err(format!(
            "unsupported endpoint: path {} is not /",
            url.path()
        ));
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "unsupported endpoint: no port".to_string())?;
    let address = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .next()
        .ok_or_else(|| "unsupported endpoint: no address".to_string())?;
    let timeout_ms = timeout.as_millis();
    let deadline = Instant::now() + timeout;
    let remaining = || -> Result<Duration, String> {
        let now = Instant::now();
        if now >= deadline {
            Err(format!("timed out after {timeout_ms} ms"))
        } else {
            Ok(deadline - now)
        }
    };
    let mut stream =
        TcpStream::connect_timeout(&address, remaining()?).map_err(|error| error.to_string())?;
    let request = format!(
        "POST {SYSTEMONE_PATH} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let send = |stream: &mut TcpStream| -> Result<(), String> {
        for chunk in [request.as_bytes(), body] {
            let mut written = 0usize;
            while written < chunk.len() {
                stream
                    .set_write_timeout(Some(remaining()?))
                    .map_err(|error| error.to_string())?;
                match stream.write(&chunk[written..]) {
                    Ok(0) => return Err("failed to write request".to_string()),
                    Ok(count) => written += count,
                    Err(error) => {
                        if Instant::now() >= deadline {
                            return Err(format!("timed out after {timeout_ms} ms"));
                        }
                        return Err(error.to_string());
                    }
                }
            }
        }
        Ok(())
    };
    send(&mut stream)?;
    let mut raw = Vec::new();
    let mut buffer = [0u8; 16384];
    loop {
        stream
            .set_read_timeout(Some(remaining()?))
            .map_err(|error| error.to_string())?;
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                raw.extend_from_slice(&buffer[..count]);
                if raw.len() > MAX_RESPONSE_BODY_BYTES + 16384 {
                    return Err("response too large".to_string());
                }
            }
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(format!("timed out after {timeout_ms} ms"));
                }
                return Err(error.to_string());
            }
        }
    }
    let header_end = find_subslice(&raw, b"\r\n\r\n").ok_or("malformed HTTP response")?;
    let header_text = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "malformed HTTP response".to_string())?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or("malformed HTTP response")?;
    if !(status_line.starts_with("HTTP/1.1 ") || status_line.starts_with("HTTP/1.0 ")) {
        return Err("malformed HTTP response".to_string());
    }
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "malformed HTTP response".to_string())?;
    if code != 200 {
        return Err(format!("HTTP status {code}"));
    }
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "malformed HTTP response".to_string())?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
        if name == "content-length" {
            content_length = value.parse().ok();
        }
    }
    let body_bytes = &raw[header_end + 4..];
    let decoded = if chunked {
        decode_chunked(body_bytes)?
    } else if let Some(length) = content_length {
        if body_bytes.len() < length {
            return Err("truncated HTTP response".to_string());
        }
        body_bytes[..length].to_vec()
    } else {
        body_bytes.to_vec()
    };
    if decoded.len() > MAX_RESPONSE_BODY_BYTES {
        return Err("response too large".to_string());
    }
    Ok(decoded)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub fn consult_decision_provider(
    config: &DecisionProviderConfig,
    question: &DecisionQuestion,
) -> DecisionAdoption {
    let fallback = |outcome: DecisionAdoptionOutcome, reason: String| DecisionAdoption {
        decision_model: config.model.clone(),
        decision_model_version: "unknown".to_string(),
        threshold_basis_points: config.threshold_basis_points,
        probabilities: Vec::new(),
        proposed_option_id: None,
        confidence_basis_points: None,
        outcome,
        adopted: false,
        reason,
        deterministic_choice: question.deterministic_choice.clone(),
        final_choice: question.deterministic_choice.clone(),
    };
    if question.options.len() < 2 {
        return fallback(
            DecisionAdoptionOutcome::NotConsulted,
            "fewer than two admitted options; the provider was not consulted".to_string(),
        );
    }
    if config.threshold_basis_points == 0 || config.threshold_basis_points > 10000 {
        return fallback(
            DecisionAdoptionOutcome::NotConsulted,
            format!(
                "threshold {} bp out of range; the provider was not consulted",
                config.threshold_basis_points
            ),
        );
    }
    if config.timeout_ms == 0 || config.timeout_ms > 60000 {
        return fallback(
            DecisionAdoptionOutcome::NotConsulted,
            format!(
                "timeout {} ms out of range; the provider was not consulted",
                config.timeout_ms
            ),
        );
    }
    let request = serde_json::to_vec(&systemone_request(question, &config.model))
        .map_err(|error| error.to_string())
        .and_then(|body| {
            post_systemone(
                &config.endpoint,
                &body,
                Duration::from_millis(config.timeout_ms),
            )
        });
    let body = match request {
        Ok(body) => body,
        Err(error) => {
            return fallback(
                DecisionAdoptionOutcome::ProviderError,
                format!("provider request failed: {error}"),
            )
        }
    };
    let proposal = match parse_systemone_response(question, &config.model, &body) {
        Ok(proposal) => proposal,
        Err(error) => {
            return fallback(
                DecisionAdoptionOutcome::ProviderError,
                format!("provider response rejected: {error}"),
            )
        }
    };
    adopt_decision_proposal(question, &proposal, config.threshold_basis_points)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn question() -> DecisionQuestion {
        let mut provenance =
            crate::selection::select(&crate::selection::selection_test_base_input())
                .expect("base input selects");
        let template = provenance
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.eligible)
            .expect("an eligible candidate")
            .clone();
        let mut ineligible = template.clone();
        ineligible.candidate.model = "model-ineligible".to_string();
        ineligible.eligible = false;
        let mut first = template.clone();
        first.candidate.model = "model-a".to_string();
        let mut second = template.clone();
        second.candidate.model = "model-b".to_string();
        provenance.candidate_set = vec![first, ineligible, second];
        if let Some(choice) = provenance.choice.as_mut() {
            choice.candidate = provenance.candidate_set[0].candidate.clone();
        }
        crate::selection::decision_proposal::decision_question("sample task", &provenance)
    }

    fn config(endpoint: String, timeout_ms: u64) -> DecisionProviderConfig {
        DecisionProviderConfig {
            endpoint,
            model: "model-a".to_string(),
            threshold_basis_points: 6000,
            timeout_ms,
        }
    }

    fn answer_body(probabilities: &str) -> String {
        format!(
            "{{\"model\":\"served-model\",\"answers\":{{\"binding\":{{\"type\":\"choice\",\"choice\":\"option-2\",\"confidence\":0.8,\"probabilities\":{probabilities}}}}}}}"
        )
    }

    fn response_with_body(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn fake_endpoint(
        response: Vec<u8>,
        sleep_ms: u64,
    ) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept one connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let mut captured = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        captured.extend_from_slice(&buffer[..count]);
                        let header_end = find_subslice(&captured, b"\r\n\r\n");
                        let complete = header_end.is_some_and(|end| {
                            let headers = String::from_utf8_lossy(&captured[..end]).to_lowercase();
                            let length = headers
                                .lines()
                                .find_map(|line| line.strip_prefix("content-length:"))
                                .and_then(|value| value.trim().parse::<usize>().ok());
                            length.is_some_and(|length| captured.len() >= end + 4 + length)
                        });
                        if complete {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            if sleep_ms > 0 {
                std::thread::sleep(Duration::from_millis(sleep_ms));
            }
            let _ = stream.write_all(&response);
            captured
        });
        (format!("http://{address}"), handle)
    }

    #[test]
    fn request_carries_only_admitted_options() {
        let question = question();
        let request = systemone_request(&question, "model-a");
        assert_eq!(request["model"], "model-a");
        assert_eq!(request["state"]["task"], "sample task");
        let binding = &request["questions"]["binding"];
        assert_eq!(binding["type"], "choice");
        let criteria = binding["criteria"].as_object().expect("criteria object");
        assert_eq!(criteria.len(), 2);
        for option in &question.options {
            assert_eq!(criteria[option.option_id.as_str()], option.description);
        }
        assert!(!criteria.values().any(|value| value
            .as_str()
            .unwrap_or_default()
            .contains("model-ineligible")));
    }

    #[test]
    fn response_parsing_converts_probabilities_and_rejects_bad_answers() {
        let question = question();
        let body = answer_body("{\"option-2\":0.8,\"option-1\":0.2}");
        let proposal = parse_systemone_response(&question, "requested-model", body.as_bytes())
            .expect("valid answer parses");
        assert_eq!(proposal.decision_model, "requested-model");
        assert_eq!(proposal.decision_model_version, "served-model");
        assert_eq!(
            proposal.probabilities,
            vec![
                DecisionOptionProbability {
                    option_id: "option-1".to_string(),
                    probability_basis_points: 2000,
                },
                DecisionOptionProbability {
                    option_id: "option-2".to_string(),
                    probability_basis_points: 8000,
                },
            ]
        );
        let bad_bodies = [
            "not json".to_string(),
            "{\"answers\":{}}".to_string(),
            "{\"model\":\"served-model\"}".to_string(),
            "{\"model\":\"served-model\",\"answers\":{\"binding\":{\"type\":\"score\",\"probabilities\":{\"option-1\":0.5}}}}".to_string(),
            "{\"model\":\"served-model\",\"answers\":{\"binding\":{\"type\":\"choice\",\"probabilities\":{\"option-1\":1.5}}}}".to_string(),
            "{\"model\":\"served-model\",\"answers\":{\"binding\":{\"type\":\"choice\",\"probabilities\":{\"option-1\":-0.1}}}}".to_string(),
        ];
        for bad in &bad_bodies {
            assert!(
                parse_systemone_response(&question, "requested-model", bad.as_bytes()).is_err(),
                "body should be rejected: {bad}"
            );
        }
    }

    #[test]
    fn consult_adopts_through_a_fake_endpoint() {
        let question = question();
        let body = answer_body("{\"option-1\":0.2,\"option-2\":0.8}");
        let (endpoint, handle) = fake_endpoint(response_with_body(&body), 0);
        let adoption = consult_decision_provider(&config(endpoint, 5000), &question);
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::Adopted);
        assert_eq!(
            adoption.final_choice,
            Some(question.options[1].candidate.clone())
        );
        assert_eq!(adoption.decision_model_version, "served-model");
        let captured = handle.join().expect("join fake endpoint");
        let text = String::from_utf8(captured).expect("captured request is utf-8");
        assert!(text.starts_with("POST /v1/systemone HTTP/1.1\r\n"));
        assert!(text.contains("Content-Type: application/json"));
        let body_start = text.find("\r\n\r\n").expect("header end") + 4;
        let parsed: serde_json::Value =
            serde_json::from_str(&text[body_start..]).expect("request body is JSON");
        assert_eq!(parsed, systemone_request(&question, "model-a"));
        let first = &body[..body.len() / 2];
        let rest = &body[body.len() / 2..];
        let chunked = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{first}\r\n{:x}\r\n{rest}\r\n0\r\n\r\n",
            first.len(),
            rest.len()
        )
        .into_bytes();
        let (endpoint, handle) = fake_endpoint(chunked, 0);
        let adoption = consult_decision_provider(&config(endpoint, 5000), &question);
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::Adopted);
        handle.join().expect("join fake endpoint");
    }

    #[test]
    fn consult_falls_back_on_errors_and_timeouts() {
        let question = question();
        let deterministic = question.deterministic_choice.clone();
        let internal_error =
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (endpoint, handle) = fake_endpoint(internal_error, 0);
        let adoption = consult_decision_provider(&config(endpoint, 5000), &question);
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::ProviderError);
        assert!(!adoption.adopted);
        assert_eq!(adoption.final_choice, deterministic);
        handle.join().expect("join fake endpoint");
        let (endpoint, handle) = fake_endpoint(response_with_body("not json"), 0);
        let adoption = consult_decision_provider(&config(endpoint, 5000), &question);
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::ProviderError);
        assert!(!adoption.adopted);
        assert_eq!(adoption.final_choice, deterministic);
        handle.join().expect("join fake endpoint");
        let body = answer_body("{\"option-1\":0.2,\"option-2\":0.8}");
        let (endpoint, handle) = fake_endpoint(response_with_body(&body), 2000);
        let adoption = consult_decision_provider(&config(endpoint, 200), &question);
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::ProviderError);
        assert!(!adoption.adopted);
        assert_eq!(adoption.final_choice, deterministic);
        handle.join().expect("join fake endpoint");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local address").port();
        drop(listener);
        let adoption =
            consult_decision_provider(&config(format!("http://127.0.0.1:{port}"), 5000), &question);
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::ProviderError);
        assert!(!adoption.adopted);
        assert_eq!(adoption.final_choice, deterministic);
        let half = answer_body("{\"option-1\":0.3,\"option-2\":0.2}");
        let (endpoint, handle) = fake_endpoint(response_with_body(&half), 0);
        let adoption = consult_decision_provider(&config(endpoint, 5000), &question);
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::Malformed);
        handle.join().expect("join fake endpoint");
    }

    #[test]
    fn consult_skips_unsupported_endpoints_and_trivial_questions() {
        let question = question();
        for endpoint in [
            "https://127.0.0.1:1",
            "http://user:pw@127.0.0.1:1",
            "http://127.0.0.1:1/api",
            "http://127.0.0.1:1/?q=1",
        ] {
            let adoption =
                consult_decision_provider(&config(endpoint.to_string(), 5000), &question);
            assert_eq!(adoption.outcome, DecisionAdoptionOutcome::ProviderError);
            assert!(
                adoption.reason.contains("unsupported endpoint"),
                "{endpoint}"
            );
        }
        let mut single = question.clone();
        single.options.truncate(1);
        let adoption =
            consult_decision_provider(&config("http://127.0.0.1:1".to_string(), 5000), &single);
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::NotConsulted);
        let adoption = consult_decision_provider(
            &DecisionProviderConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                model: "model-a".to_string(),
                threshold_basis_points: 0,
                timeout_ms: 5000,
            },
            &question,
        );
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::NotConsulted);
        let adoption = consult_decision_provider(
            &DecisionProviderConfig {
                endpoint: "http://127.0.0.1:1".to_string(),
                model: "model-a".to_string(),
                threshold_basis_points: 6000,
                timeout_ms: 0,
            },
            &question,
        );
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::NotConsulted);
        assert_eq!(
            serde_json::to_string(&DecisionAdoptionOutcome::ProviderError).expect("serializes"),
            "\"provider_error\""
        );
    }
}
