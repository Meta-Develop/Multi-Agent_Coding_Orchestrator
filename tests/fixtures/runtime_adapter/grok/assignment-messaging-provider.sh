#!/bin/sh
# Non-inference Grok-shaped provider: runs the assignment-messaging IPC child probe inside
# the confined external-agent launch, then emits the bounded streaming-json fixture.
# POSIX sh only: ExternalGrok confinement admits this executable, not ambient interpreters.
# Probe path and phase/filter live in an embedded manifest under the admitted worktree (verified
# ExternalGrok clears arbitrary MACO_TEST_* parent env). Parent helper is subprocess-isolated.
set -eu

prompt_file=0
model=0
effort=0
cwd=0
json_schema=0
output_format=0
sandbox=0
always_approve=0
disable_web_search=0
no_memory=0
no_subagents=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prompt-file)
            [ "$#" -ge 2 ] || exit 1
            prompt_file=$((prompt_file + 1))
            shift 2
            ;;
        --model)
            [ "$#" -ge 2 ] || exit 1
            [ "$2" = "grok-4.6" ] || {
                printf '%s\n' "unexpected model" >&2
                exit 1
            }
            model=$((model + 1))
            shift 2
            ;;
        --reasoning-effort)
            [ "$#" -ge 2 ] || exit 1
            [ "$2" = "xhigh" ] || {
                printf '%s\n' "unexpected reasoning effort" >&2
                exit 1
            }
            effort=$((effort + 1))
            shift 2
            ;;
        --cwd)
            [ "$#" -ge 2 ] || exit 1
            cwd=$((cwd + 1))
            shift 2
            ;;
        --json-schema)
            [ "$#" -ge 2 ] || exit 1
            case "$2" in
                \{*) ;;
                *)
                    printf '%s\n' "json-schema is not an inline object" >&2
                    exit 1
                    ;;
            esac
            json_schema=$((json_schema + 1))
            shift 2
            ;;
        --output-format)
            [ "$#" -ge 2 ] || exit 1
            [ "$2" = "streaming-json" ] || {
                printf '%s\n' "output format must stay streaming-json" >&2
                exit 1
            }
            output_format=$((output_format + 1))
            shift 2
            ;;
        --sandbox)
            [ "$#" -ge 2 ] || exit 1
            [ "$2" = "strict" ] || {
                printf '%s\n' "sandbox must stay strict" >&2
                exit 1
            }
            sandbox=$((sandbox + 1))
            shift 2
            ;;
        --always-approve)
            always_approve=$((always_approve + 1))
            shift
            ;;
        --disable-web-search)
            disable_web_search=$((disable_web_search + 1))
            shift
            ;;
        --no-memory)
            no_memory=$((no_memory + 1))
            shift
            ;;
        --no-subagents)
            no_subagents=$((no_subagents + 1))
            shift
            ;;
        *)
            printf '%s\n' "unexpected grok argv: $1" >&2
            exit 1
            ;;
    esac
done

for count in \
    "$prompt_file" \
    "$model" \
    "$effort" \
    "$cwd" \
    "$json_schema" \
    "$output_format" \
    "$sandbox" \
    "$always_approve" \
    "$disable_web_search" \
    "$no_memory" \
    "$no_subagents"
do
    [ "$count" -eq 1 ] || {
        printf '%s\n' "immutable grok argv was not exact" >&2
        exit 1
    }
done

FIXTURE_MANIFEST=@@MACO_ASSIGNMENT_MESSAGING_FIXTURE_MANIFEST@@
if [ ! -r "$FIXTURE_MANIFEST" ]; then
    printf '%s\n' "missing assignment messaging fixture manifest" >&2
    exit 1
fi
# shellcheck disable=SC1090
. "$FIXTURE_MANIFEST"
binary="${PROBE_BINARY:?missing PROBE_BINARY in fixture manifest}"
filter="${EXACT_FILTER:?missing EXACT_FILTER in fixture manifest}"
phase="${PHASE:?missing PHASE in fixture manifest}"
result_file="${RESULT_FILE:?missing RESULT_FILE in fixture manifest}"
export MACO_TEST_ASSIGNMENT_MESSAGING_CHILD=1
export MACO_TEST_MESSAGING_PHASE="$phase"
export MACO_TEST_RESULT_FILE="$result_file"
if [ -n "${DISPOSABLE_PEER_PID:-}" ]; then
    export MACO_TEST_DISPOSABLE_PEER_PID="$DISPOSABLE_PEER_PID"
else
    unset MACO_TEST_DISPOSABLE_PEER_PID
fi
"$binary" --exact "$filter" --nocapture --quiet >&2

printf '%s' @@MACO_ASSIGNMENT_MESSAGING_FIXTURE_STREAM@@
