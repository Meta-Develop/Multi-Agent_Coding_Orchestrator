#!/bin/sh
# Selected writable Grok ACP executable fixture. Validates argv + admitted GROK_HOME
# projection, then speaks parent ACP stdio. POSIX sh only: Verified ExternalGrok
# confinement exposes this one executable, not sibling interpreters or helpers.
# Synthetic model/cost only — not production account economics.
set -eu

MODE="${MACO_WRITABLE_GROK_ACP_FIXTURE_MODE:-success}"
SESSION="maco-fixture-acp-session"
RESOLVED_MODEL="grok-4.6"
RESOLVED_EFFORT="xhigh"
COST_TICKS=20000000

expected_count=13
if [ "$#" -ne "$expected_count" ]; then
	printf '%s\n' "unexpected argv count: $#" "$@" >&2
	exit 2
fi
if [ "$1" != "--sandbox" ] \
	|| [ "$2" != "strict" ] \
	|| [ "$3" != "--always-approve" ] \
	|| [ "$4" != "--disable-web-search" ] \
	|| [ "$5" != "--no-memory" ] \
	|| [ "$6" != "--no-subagents" ] \
	|| [ "$7" != "agent" ] \
	|| [ "$8" != "--no-leader" ] \
	|| [ "$9" != "-m" ] \
	|| [ "${10}" != "grok-4.6" ] \
	|| [ "${11}" != "--reasoning-effort" ] \
	|| [ "${12}" != "xhigh" ] \
	|| [ "${13}" != "stdio" ]; then
	printf '%s\n' "unexpected argv:" "$@" >&2
	exit 2
fi

if [ -z "${GROK_HOME:-}" ] || [ "$HOME" != "$GROK_HOME" ]; then
	printf '%s\n' "GROK_HOME projection missing" >&2
	exit 3
fi
if [ ! -r "$GROK_HOME/auth.json" ]; then
	printf '%s\n' "admitted auth fixture unreadable" >&2
	exit 3
fi
if [ -e "$GROK_HOME/ambient-secret" ]; then
	printf '%s\n' "ambient credential leaked into child" >&2
	exit 3
fi

printf '%s\n' 'approval-contract:sandbox=strict;headless=always-approve;web-search=disabled;memory=disabled;subagents=disabled' >&2

send() {
	printf '%s\n' "$1"
}

json_id() {
	_rest=${1#*\"id\":}
	_id=${_rest%%,*}
	_id=${_id%%\}*}
	printf '%s' "$_id"
}

json_method() {
	_rest=${1#*\"method\":\"}
	_method=${_rest%%\"*}
	printf '%s' "$_method"
}

recv() {
	IFS= read -r line || exit 0
}

recv
[ "$(json_method "$line")" = "initialize" ]
send "{\"jsonrpc\":\"2.0\",\"id\":$(json_id "$line"),\"result\":{\"protocolVersion\":1}}"

recv
[ "$(json_method "$line")" = "session/new" ]
send "{\"jsonrpc\":\"2.0\",\"id\":$(json_id "$line"),\"result\":{\"sessionId\":\"$SESSION\"}}"

recv
[ "$(json_method "$line")" = "session/set_model" ]
send "{\"jsonrpc\":\"2.0\",\"method\":\"_x.ai/session_notification\",\"params\":{\"sessionId\":\"$SESSION\",\"update\":{\"sessionUpdate\":\"model_changed\",\"model_id\":\"$RESOLVED_MODEL\",\"reasoning_effort\":\"$RESOLVED_EFFORT\"}}}"
send "{\"jsonrpc\":\"2.0\",\"id\":$(json_id "$line"),\"result\":{\"_meta\":{\"model\":\"$RESOLVED_MODEL\"}}}"

while :; do
	recv
	method=$(json_method "$line")
	id=$(json_id "$line")
	case "$method" in
	session/prompt)
		if [ "$MODE" = "permission" ]; then
			send "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"session/request_permission\",\"params\":{\"sessionId\":\"$SESSION\",\"toolCallId\":\"tc-fixture-deny\",\"options\":[]}}"
			recv
		elif [ "$MODE" = "outside_write" ]; then
			printf '%s\n' "must not persist" >../outside-untouched.txt || true
		fi
		if [ "$MODE" = "success" ]; then
			printf '%s\n' "bounded managed child acp write" >bounded-result.txt
		fi
		incomplete=false
		if [ "$MODE" = "incomplete" ]; then
			incomplete=true
		fi
		send "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"stopReason\":\"end_turn\",\"text\":\"fixture-acp-response\",\"usage_is_incomplete\":$incomplete,\"cost_is_partial\":false,\"_meta\":{\"structuredOutput\":{\"accepted\":true,\"path\":\"bounded-result.txt\"},\"usage\":{\"inputTokens\":11,\"outputTokens\":3,\"costUsdTicks\":$COST_TICKS}}}}"
		# Keep a successful session alive until the parent sends teardown cancel.
		if [ "$MODE" = "success" ]; then
			continue
		fi
		break
		;;
	terminal/create)
		send "{\"jsonrpc\":\"2.0\",\"id\":$id,\"error\":{\"code\":-32601,\"message\":\"forbidden\"}}"
		;;
	session/cancel)
		if [ -n "$id" ]; then
			send "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{}}"
		fi
		break
		;;
	esac
done
