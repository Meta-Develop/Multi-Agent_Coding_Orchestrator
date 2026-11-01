use super::*;

const PACKET_LIMIT: usize = 128 * 1024;

fn json_line(value: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn padded_lines(mut lines: Vec<Vec<u8>>, size: usize, pad_line: usize) -> Vec<u8> {
    let missing = size - lines.iter().map(Vec::len).sum::<usize>();
    // JSON permits whitespace after an object, before the newline.
    let end = lines[pad_line].len() - 1;
    lines[pad_line].splice(end..end, std::iter::repeat_n(b' ', missing));
    lines.concat()
}

fn packet(journal: &[u8], stream: &[u8], workers: usize) -> Result<Value> {
    let (_temp, repo) = injected_repository();
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        RunId::new("operation-evidence")?,
        "operation-evidence-test",
    )?;
    let mut journals = WorkerExecutionJournalEvidenceSet::new();
    for index in 0..workers {
        let worker = format!("worker-{index}");
        let root = PathBuf::from(format!("nested/parent/attempt-1/{worker}"));
        let path = root.join(format!("journals/{worker}.jsonl"));
        writer.write_bytes(&path, journal, ArtifactFileDisposition::PrivateEvidence)?;
        writer.write_bytes(
            root.join("stdout.jsonl"),
            stream,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        journals.insert(
            worker,
            WorkerExecutionJournalEvidence {
                incoming_relative_path: path.clone(),
                evidence_relative_path: path,
                command_binding: None,
                status: WorkerExecutionJournalStatus::Loaded(Vec::new()),
            },
        );
    }
    assignment_execution::worker_review_evidence_for_test(&writer, &journals)
}

fn assert_source_partition(evidence: &Value, original: &[u8]) {
    assert_eq!(evidence["original_bytes"], original.len());
    assert_eq!(
        evidence["sha256"],
        crate::artifacts::state_auth::sha256_hex(original)
    );
    let lines = original
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    let mut coverage = vec![false; original.len()];
    let mut selected = 0;
    for record in evidence["records"]
        .as_array()
        .expect("complete record array")
    {
        let start = record["byte_start"].as_u64().unwrap() as usize;
        let end = record["byte_end"].as_u64().unwrap() as usize;
        let line = record["line"].as_u64().unwrap() as usize;
        assert_eq!(&original[start..end], lines[line - 1]);
        assert_eq!(
            record["sha256"],
            crate::artifacts::state_auth::sha256_hex(&original[start..end])
        );
        assert_eq!(
            record["content"],
            std::str::from_utf8(&original[start..end]).unwrap()
        );
        for covered in &mut coverage[start..end] {
            assert!(!*covered);
            *covered = true;
        }
        selected += end - start;
    }
    let manifest = &evidence["omission_manifest"];
    let mut omitted = 0;
    let mut count = 0;
    for range in manifest["ranges"]
        .as_array()
        .expect("explicit omission manifest")
    {
        let start = range["byte_start"].as_u64().unwrap() as usize;
        let end = range["byte_end"].as_u64().unwrap() as usize;
        let first = range["first_line"].as_u64().unwrap() as usize;
        let last = range["last_line"].as_u64().unwrap() as usize;
        assert_eq!(range["records"], last - first + 1);
        assert_eq!(
            range["sha256"],
            crate::artifacts::state_auth::sha256_hex(&original[start..end])
        );
        assert_eq!(&original[start..end], lines[first - 1..last].concat());
        for covered in &mut coverage[start..end] {
            assert!(!*covered);
            *covered = true;
        }
        omitted += end - start;
        count += last - first + 1;
    }
    assert!(coverage.into_iter().all(|covered| covered));
    assert_eq!(selected + omitted, original.len());
    assert_eq!(manifest["omitted_bytes"], omitted);
    assert_eq!(manifest["omitted_records"], count);
    assert_eq!(evidence["record_count"], lines.len());
}

#[test]
fn q714_operation_records_survive_audit_04_shape() -> Result<()> {
    let commands = [
        "cat target.py",
        "cat target.py",
        "native-edit-baseline",
        "native-edit",
        "unittest",
        "unittest",
        "git diff --check",
        "git diff --check",
        "git diff",
        "git diff",
    ];
    let journal = padded_lines(commands.iter().enumerate().map(|(i, command)| json_line(json!({
        "command":[command], "cwd":"/workspace", "changed_paths":if i == 3 {vec!["target.py"]} else {vec![]},
        "observation":{"phase":if i == 2 {"started"} else if i == 3 {"native_edit"} else if i % 2 == 0 {"started"} else {"completed"}}
    }))).collect(), 10_049, 0);
    // Preserve -04's operation line positions and complete record sizes.
    let operation_sizes = [
        (48, 3734),
        (49, 4494),
        (55, 1764),
        (56, 1761),
        (59, 870),
        (61, 873),
        (62, 878),
        (65, 878),
        (67, 1764),
        (68, 1761),
        (71, 878),
        (73, 1944),
        (74, 2288),
        (77, 878),
        (79, 1774),
        (80, 1772),
        (83, 878),
        (85, 1916),
        (87, 2631),
        (90, 878),
        (1895, 878),
    ];
    let operations = operation_sizes.map(|(line, _)| line);
    let stream = padded_lines((1..=1897).map(|line| {
        if operations.contains(&line) {
            let record = json_line(json!({"method":if [62,65,71,77,83,90,1895].contains(&line) {"turn/diff/updated"} else if [48,55,59,67,73,79,85].contains(&line) {"item/started"} else {"item/completed"}, "params":{"item":{
                "type":if [59,61].contains(&line) {"fileChange"} else {"commandExecution"}, "id":format!("operation-{line}"),
                "command":if line >= 85 {"git diff; git status --short"} else if line >= 73 {"python3 -m unittest"} else {"cat target.py"},
                "aggregatedOutput":format!("required-operation-{line}")}}}));
            let size = operation_sizes.iter().find(|(number, _)| *number == line).unwrap().1;
            padded_lines(vec![record], size, 0)
        } else {
            json_line(json!({"method":"item/reasoning/textDelta", "params":{"delta":"irrelevant reasoning"}}))
        }
    }).collect(), 573_420, 0);
    let value = packet(&journal, &stream, 1)?;
    assert!(serde_json::to_vec(&value)?.len() <= PACKET_LIMIT);
    for entry in value.as_array().unwrap() {
        let evidence = &entry["evidence"];
        if entry["kind"] == "worker_journal" {
            assert_source_partition(evidence, &journal);
            assert_eq!(evidence["records"].as_array().unwrap().len(), 10);
            assert_eq!(evidence["omission_manifest"]["omitted_records"], 0);
        } else {
            assert_source_partition(evidence, &stream);
            let selected = evidence["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|record| record["line"].as_u64().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(selected, operations);
            assert_eq!(
                evidence["omission_manifest"]["omitted_records"],
                1897 - operations.len()
            );
            assert_eq!(evidence["omission_manifest"]["required_records_omitted"], 0);
        }
    }
    Ok(())
}

#[test]
fn q714_oversized_operation_is_manifested_without_partial_record() -> Result<()> {
    let journal = [
        json_line(json!({"command":["cat target.py"],"output":"x".repeat(PACKET_LIMIT)})),
        json_line(json!({"command":["unittest"]})),
    ]
    .concat();
    let stream = [json_line(json!({"method":"item/completed", "params":{"item":{"type":"commandExecution","id":"huge","aggregatedOutput":"y".repeat(PACKET_LIMIT)}}})), json_line(json!({"method":"item/completed","params":{"item":{"type":"fileChange","id":"small"}}}))].concat();
    let value = packet(&journal, &stream, 1)?;
    assert!(serde_json::to_vec(&value)?.len() <= PACKET_LIMIT);
    for entry in value.as_array().unwrap() {
        let original = if entry["kind"] == "worker_journal" {
            &journal
        } else {
            &stream
        };
        let evidence = &entry["evidence"];
        assert_source_partition(evidence, original);
        assert_eq!(evidence["records"].as_array().unwrap().len(), 1);
        assert_eq!(evidence["records"][0]["line"], 2);
        assert_eq!(evidence["omission_manifest"]["required_records_omitted"], 1);
        assert_eq!(
            evidence["omission_manifest"]["ranges"][0]["reasons"]["record_exceeds_source_budget"],
            1
        );
    }
    Ok(())
}

#[test]
fn q714_packet_budget_covers_multiple_workers_and_manifests() -> Result<()> {
    let journal = (0..150)
        .map(|i| json_line(json!({"command":["read", &format!("{i}")]})))
        .collect::<Vec<_>>()
        .concat();
    let stream = (0..150).map(|i| json_line(json!({"method":"item/completed","params":{"item":{"type":"commandExecution","id":i}}}))).collect::<Vec<_>>().concat();
    let value = packet(&journal, &stream, 8)?;
    assert!(serde_json::to_vec(&value)?.len() <= PACKET_LIMIT);
    for entry in value.as_array().unwrap() {
        assert_source_partition(
            &entry["evidence"],
            if entry["kind"] == "worker_journal" {
                &journal
            } else {
                &stream
            },
        );
        assert!(
            entry["evidence"]["omission_manifest"]["required_records_omitted"]
                .as_u64()
                .unwrap()
                > 0
        );
    }
    Ok(())
}
