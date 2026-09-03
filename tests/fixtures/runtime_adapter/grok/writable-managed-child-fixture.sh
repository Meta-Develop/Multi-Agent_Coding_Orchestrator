#!/bin/sh
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

printf '%s\n' 'bounded managed child write' > bounded-result.txt
stream="$(dirname "$0")/writable-managed-child.streaming-json"
cat "$stream"
