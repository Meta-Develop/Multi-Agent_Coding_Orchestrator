use super::*;

#[derive(Debug, PartialEq, Eq)]
enum Word {
    Literal(String),
    Timestamp,
}

impl Word {
    fn literal(&self) -> Option<&str> {
        match self {
            Self::Literal(value) => Some(value),
            Self::Timestamp => None,
        }
    }

    fn matches_timestamp(&self, timestamp: &str) -> bool {
        !timestamp.is_empty()
            && match self {
                Self::Literal(value) => value == timestamp,
                Self::Timestamp => true,
            }
    }
}

/// This is reporting normalization, not execution evidence. Only launcher-held
/// bindings and an already validated, finished journal record can support it.
pub(super) fn canonicalize_wrapper(
    record: &CommandRunRecord,
    journal: &WorkerExecutionJournalEvidence,
    entries: &[WorkerExecutionJournalEntry],
) -> Option<Vec<String>> {
    canonicalize_command(&record.command, &record.cwd, journal, entries)
}

pub(super) fn canonicalize_command(
    command: &[String],
    cwd: &Path,
    journal: &WorkerExecutionJournalEvidence,
    entries: &[WorkerExecutionJournalEntry],
) -> Option<Vec<String>> {
    let binding = journal.command_binding.as_ref()?;
    if cwd.as_os_str() != binding.cwd.as_os_str() {
        return None;
    }
    let words = match command {
        [shell, flag, script]
            if matches!(shell.as_str(), "/bin/bash" | "bash")
                && matches!(flag.as_str(), "-lc" | "-c") =>
        {
            shell_wrapper_words(script)?
        }
        argv => argv.iter().cloned().map(Word::Literal).collect(),
    };
    if words.first()?.literal()? != binding.executable.to_str()?
        || words.get(1)?.literal()? != "supervise"
        || words.get(2)?.literal()? != "journal-append"
    {
        return None;
    }

    let separator = words.iter().position(|word| word.literal() == Some("--"))?;
    let mut flags = BTreeMap::new();
    let mut declared_paths = Vec::new();
    let mut observe = false;
    let mut auto_timestamps = false;
    let mut cursor = 3;
    while cursor < separator {
        let flag = words[cursor].literal()?;
        cursor += 1;
        if flag == "--observe-changes" {
            if observe {
                return None;
            }
            observe = true;
            continue;
        }
        if flag == "--auto-timestamps" {
            if auto_timestamps {
                return None;
            }
            auto_timestamps = true;
            continue;
        }
        let (name, value) = if let Some((name, value)) = flag.split_once('=') {
            (name, Word::Literal(value.to_string()))
        } else {
            if cursor >= separator {
                return None;
            }
            let value = match &words[cursor] {
                Word::Literal(value) => Word::Literal(value.clone()),
                Word::Timestamp => Word::Timestamp,
            };
            cursor += 1;
            (flag, value)
        };
        if name == "--changed-path" {
            if value
                .literal()?
                .trim_matches(|c| matches!(c, ' ' | '\t' | '\n'))
                .is_empty()
            {
                return None;
            }
            declared_paths.push(PathBuf::from(value.literal()?));
        } else if !matches!(
            name,
            "--journal"
                | "--device"
                | "--inode"
                | "--cwd"
                | "--start-timestamp"
                | "--end-timestamp"
        ) || flags.insert(name, value).is_some()
        {
            return None;
        }
    }
    if flags.get("--journal")?.literal()? != binding.journal.to_str()?
        || flags.get("--device")?.literal()?.parse::<u64>().ok()? != binding.device
        || flags.get("--inode")?.literal()?.parse::<u64>().ok()? != binding.inode
        || flags.get("--cwd")?.literal()? != binding.cwd.to_str()?
    {
        return None;
    }
    let command = words
        .get(separator + 1..)?
        .iter()
        .map(|word| word.literal().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    if command.is_empty() {
        return None;
    }
    let automatic = Word::Timestamp;
    let (start, end) = if auto_timestamps {
        if flags.contains_key("--start-timestamp") || flags.contains_key("--end-timestamp") {
            return None;
        }
        (&automatic, &automatic)
    } else {
        (
            flags.get("--start-timestamp")?,
            flags.get("--end-timestamp")?,
        )
    };
    let declared_paths = normalize_paths(declared_paths).ok()?;
    let candidates = entries
        .iter()
        .filter(|entry| {
            entry.command == command
                && entry.cwd.as_os_str() == binding.cwd.as_os_str()
                && entry.observation.as_ref().is_some_and(|observation| {
                    observation.phase
                        == if observe {
                            WorkerJournalObservationPhase::NativeEdit
                        } else {
                            WorkerJournalObservationPhase::Completed
                        }
                })
        })
        .collect::<Vec<_>>();
    let repeated = candidates.len() > 1;
    if repeated && (start.literal().is_none() || end.literal().is_none()) {
        return None;
    }
    let mut matches = candidates.into_iter().filter(|entry| {
        start.matches_timestamp(&entry.start_timestamp)
            && end.matches_timestamp(&entry.end_timestamp)
            && ((!repeated && declared_paths.is_empty()) || declared_paths == entry.changed_paths)
    });
    let matched = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(matched.command.clone())
}

pub(super) fn is_wrapper(command: &[String]) -> bool {
    match command {
        [_, supervise, append, ..] if supervise == "supervise" && append == "journal-append" => {
            true
        }
        [shell, flag, script]
            if matches!(shell.as_str(), "/bin/bash" | "bash")
                && matches!(flag.as_str(), "-lc" | "-c") =>
        {
            match shell_wrapper_words(script) {
                Some(words) => words.windows(2).any(|pair| {
                    pair[0].literal() == Some("supervise")
                        && pair[1].literal() == Some("journal-append")
                }),
                // Unsupported shell syntax must not hide an apparent wrapper
                // from the envelope check; this never supplies execution support.
                None => script.contains("supervise") && script.contains("journal-append"),
            }
        }
        _ => false,
    }
}

/// Accept literal shell words and timestamp-only substitutions. Never execute a
/// shell or expand report text, and reject operators, redirects and extra commands.
fn shell_wrapper_words(script: &str) -> Option<Vec<Word>> {
    let shell_space = |c: char| matches!(c, ' ' | '\t' | '\n');
    if script.chars().any(|c| c.is_whitespace() && !shell_space(c)) {
        return None;
    }
    let mut rest = script.trim_matches(shell_space);
    let mut variables = BTreeSet::new();
    while let Some((name, suffix)) = rest.split_once("=$(") {
        if !shell_name(name) {
            break;
        }
        let (date, suffix) = suffix.split_once(')')?;
        if !timestamp_command(date) || !variables.insert(name.to_string()) {
            return None;
        }
        rest = suffix
            .trim_start_matches(shell_space)
            .strip_prefix(';')?
            .trim_start_matches(shell_space);
    }
    literal_shell_words(rest, &variables)
}

fn shell_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn timestamp_command(command: &str) -> bool {
    // A small, read-only date grammar; no shell evaluation or nested expansion.
    if command.contains(['$', '`', '(', ')', '\n', '\r']) {
        return false;
    }
    let Some(words) = literal_shell_words(command, &BTreeSet::new()) else {
        return false;
    };
    let words = words.iter().filter_map(Word::literal).collect::<Vec<_>>();
    matches!(
        words.first(),
        Some(&"date" | &"/bin/date" | &"/usr/bin/date")
    ) && words.len() > 1
        && words[1..].iter().all(|word| {
            matches!(
                *word,
                "-u" | "--utc" | "--iso-8601=seconds" | "--rfc-3339=seconds"
            ) || word.strip_prefix('+').is_some_and(|format| {
                !format.is_empty()
                    && format
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "%:-_.".contains(c))
            })
        })
}

fn literal_shell_words(script: &str, variables: &BTreeSet<String>) -> Option<Vec<Word>> {
    let mut chars = script.chars().peekable();
    let mut words = Vec::new();
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|c| matches!(c, ' ' | '\t')) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut value = String::new();
        let mut dynamic = false;
        let mut quote = None;
        while let Some(&c) = chars.peek() {
            if quote.is_none() && matches!(c, ' ' | '\t') {
                break;
            }
            chars.next();
            match (quote, c) {
                (Some('\''), '\'') => quote = None,
                (Some('\''), c) => value.push(c),
                (None, '\'' | '"') => quote = Some(c),
                (Some('"'), '"') => quote = None,
                (_, '\\') => {
                    let escaped = chars.next()?;
                    if escaped == '\n' {
                        return None;
                    }
                    if quote == Some('"') && !"$`\"\\".contains(escaped) {
                        value.push('\\');
                    }
                    value.push(escaped);
                }
                (_, '$') => {
                    if dynamic || !value.is_empty() {
                        return None;
                    }
                    if chars.peek() == Some(&'(') {
                        chars.next();
                        let mut command = String::new();
                        loop {
                            let c = chars.next()?;
                            if c == ')' {
                                break;
                            }
                            command.push(c);
                        }
                        if !timestamp_command(&command) {
                            return None;
                        }
                    } else {
                        let braced = chars.peek() == Some(&'{');
                        if braced {
                            chars.next();
                        }
                        let mut name = String::new();
                        while chars
                            .peek()
                            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                        {
                            name.push(chars.next()?);
                        }
                        if !variables.contains(&name) || (braced && chars.next()? != '}') {
                            return None;
                        }
                    }
                    dynamic = true;
                }
                (_, '`')
                | (
                    None,
                    '\n' | '\r' | ';' | '&' | '|' | '<' | '>' | '(' | ')' | '#' | '*' | '?' | '['
                    | ']' | '{' | '}' | '~',
                ) => return None,
                (_, c) => {
                    if dynamic {
                        return None;
                    }
                    value.push(c);
                }
            }
        }
        if quote.is_some() || (dynamic && !value.is_empty()) {
            return None;
        }
        words.push(if dynamic {
            Word::Timestamp
        } else {
            Word::Literal(value)
        });
    }
    Some(words)
}
