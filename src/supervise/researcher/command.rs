//! Decode only the literal outer Bash argv rendered in native commandExecution events.

/// The report names the submitted script. Decode exactly one host-added wrapper;
/// never evaluate shell text, normalize the script, or unwrap a report claim.
pub(super) fn submitted_command(host_command: &str) -> Option<String> {
    let word = host_command
        .strip_prefix("/bin/bash -lc ")
        .or_else(|| host_command.strip_prefix("/bin/bash -c "))?;
    if word.is_empty() || word.contains('\0') {
        return None;
    }
    let mut chars = word.chars();
    let mut quote = None;
    let mut script = String::new();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), c) => script.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (_, '\\') => {
                let escaped = chars.next()?;
                if escaped == '\n' {
                    return None;
                }
                if quote == Some('"') && !"$`\"\\".contains(escaped) {
                    script.push('\\');
                }
                script.push(escaped);
            }
            (Some('"'), '$' | '`') => return None,
            (Some('"'), c) => script.push(c),
            (None, c) if c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c) => {
                script.push(c);
            }
            _ => return None,
        }
    }
    (quote.is_none() && !script.trim().is_empty()).then_some(script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn researcher_host_wrapper_decodes_one_literal_script_without_normalizing() {
        for (rendered, script) in [
            ("/bin/bash -lc pwd", "pwd"),
            ("/bin/bash -c 'rg API src'", "rg API src"),
            (
                "/bin/bash -lc 'ps -p $$ -o args=; :'",
                "ps -p $$ -o args=; :",
            ),
            (
                r#"/bin/bash -lc 'printf '\''%s\n'\'' "a b"'"#,
                "printf '%s\\n' \"a b\"",
            ),
            (
                r#"/bin/bash -lc "printf '%s\\n' \"\$x\"""#,
                "printf '%s\\n' \"$x\"",
            ),
            (
                "/bin/bash -lc '  printf x\n# comment\n'",
                "  printf x\n# comment\n",
            ),
            (r#"/bin/bash -lc 'a'"'"'b'"#, "a'b"),
            ("/bin/bash -lc '/bin/bash -c true'", "/bin/bash -c true"),
        ] {
            assert_eq!(submitted_command(rendered).as_deref(), Some(script));
        }
    }

    #[test]
    fn researcher_host_wrapper_rejects_expansion_extra_argv_and_unknown_syntax() {
        for rendered in [
            "rg API src",
            "/bin/sh -lc 'pwd'",
            "bash -lc 'pwd'",
            "/bin/bash -ilc 'pwd'",
            "env /bin/bash -lc 'pwd'",
            "/bin/bash -lc ",
            "/bin/bash -lc ''",
            "/bin/bash -lc ' '",
            "/bin/bash -lc 'pwd",
            "/bin/bash -lc 'pwd' extra",
            "/bin/bash -lc 'pwd'; true",
            "/bin/bash -lc 'pwd'\ntrue",
            "/bin/bash -lc 'pwd' >out",
            "/bin/bash -lc $COMMAND",
            "/bin/bash -lc \"$COMMAND\"",
            "/bin/bash -lc \"$(pwd)\"",
            "/bin/bash -lc \"`pwd`\"",
            "/bin/bash -lc ~/script",
            "/bin/bash -lc *.sh",
            "/bin/bash -lc 'pwd'\\",
            "/bin/bash -lc pw\\\nd",
            "/bin/bash -lc 'pw\0d'",
        ] {
            assert_eq!(submitted_command(rendered), None, "{rendered:?}");
        }
    }
}
