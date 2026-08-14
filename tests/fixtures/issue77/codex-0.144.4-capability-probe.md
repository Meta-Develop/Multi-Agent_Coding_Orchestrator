# Codex 0.144.4 writable app-server capability probe

Probe date: 2026-08-14 (Asia/Tokyo)

Installed binary:

```text
$ codex --version
codex-cli 0.144.4
```

Generated schema command:

```text
$ codex app-server generate-json-schema --experimental --out <temporary-directory>
```

The generated `AskForApproval` schema offered only `untrusted`, `on-request`,
`never`, and granular controls for `mcp_elicitations`, `rules`,
`sandbox_approval`, `request_permissions`, and `skill_approval`. It offered no
force-every-action or force-read-callback mode. The schema's only dedicated
approval server requests were:

```text
item/commandExecution/requestApproval
item/fileChange/requestApproval
item/permissions/requestApproval
```

The matching upstream source was OpenAI Codex tag `rust-v0.144.4`, peeled
commit `8c68d4c87dc54d38861f5114e920c3de2efa5876`. Its
`AskForApproval::OnRequest` documentation says that the model decides when to
ask. Its `AskForApproval::UnlessTrusted` documentation says known-safe
read-only commands are auto-approved. `assess_patch_safety` asks for every
patch under `UnlessTrusted`, while `OnRequest` auto-approves patches constrained
to writable roots.

## Live probe configuration

The app-server was launched over stdio with service tier `default`, a
`workspace-write` sandbox, network disabled, and `approvalsReviewer=user`.
The successful thread negotiation reported:

```json
{"approvalPolicy":"on-request","approvalsReviewer":"user","sandbox":{"type":"workspaceWrite","writableRoots":[],"networkAccess":false,"excludeTmpdirEnvVar":false,"excludeSlashTmp":false},"serviceTier":"default"}
```

Each action below ran in the disposable directory
`/tmp/maco-issue77-live.5wNBdc`. Volatile token-usage, rate-limit, reasoning,
and message-delta notifications are omitted. Absence of a request is stated
only when the complete item lifecycle contained no server request between
`item/started` and `item/completed`.

## `on-request` bypasses

Known-safe read command; no approval request:

```json
{"method":"item/started","params":{"item":{"type":"commandExecution","id":"exec-22824a90-277c-439f-b98b-cce3e3e97158","command":"/run/current-system/sw/bin/bash -lc pwd","cwd":"/tmp/maco-issue77-live.5wNBdc","processId":"60626","status":"inProgress"}}}
{"method":"item/completed","params":{"item":{"type":"commandExecution","id":"exec-22824a90-277c-439f-b98b-cce3e3e97158","status":"completed","exitCode":0}}}
```

Workspace write through shell; no approval request:

```json
{"method":"item/started","params":{"item":{"type":"commandExecution","id":"exec-f7a73830-e84b-4a6c-bdf2-26b337f7313c","command":"/run/current-system/sw/bin/bash -lc 'touch shell-write-marker'","processId":"89518","status":"inProgress"}}}
{"method":"item/completed","params":{"item":{"type":"commandExecution","id":"exec-f7a73830-e84b-4a6c-bdf2-26b337f7313c","status":"completed","exitCode":0}}}
```

Workspace write through `apply_patch`; no approval request:

```json
{"method":"item/started","params":{"item":{"type":"fileChange","id":"exec-82d12843-3e71-47cd-bede-f1bb4a541010","changes":[{"path":"/tmp/maco-issue77-live.5wNBdc/patch-write-marker","kind":{"type":"add"},"diff":"marker\n"}],"status":"inProgress"}}}
{"method":"item/completed","params":{"item":{"type":"fileChange","id":"exec-82d12843-3e71-47cd-bede-f1bb4a541010","status":"completed"}}}
```

Destructive workspace command; no approval request:

```json
{"method":"item/started","params":{"item":{"type":"commandExecution","id":"exec-ab686702-2d1f-42e5-8677-e5c66148d92d","command":"/run/current-system/sw/bin/bash -lc 'rm shell-write-marker'","processId":"13709","status":"inProgress"}}}
{"method":"item/completed","params":{"item":{"type":"commandExecution","id":"exec-ab686702-2d1f-42e5-8677-e5c66148d92d","status":"completed","exitCode":0}}}
```

Network attempt; no approval request. The sandbox denied DNS, but the attempted
action was not routed through the parent:

```json
{"method":"item/started","params":{"item":{"type":"commandExecution","id":"exec-2ba2b51f-8efb-4799-b56e-29c922ae4344","command":"/run/current-system/sw/bin/bash -lc 'curl --max-time 3 https://example.com -o network-body'","processId":"61890","status":"inProgress"}}}
{"method":"item/completed","params":{"item":{"type":"commandExecution","id":"exec-2ba2b51f-8efb-4799-b56e-29c922ae4344","status":"failed","aggregatedOutput":"curl: (6) Could not resolve host: example.com\n","exitCode":6}}}
```

## Strongest `untrusted` policy

The new thread negotiated `approvalPolicy=untrusted` and
`approvalsReviewer=user`.

Workspace file read still bypassed approval:

```json
{"method":"item/started","params":{"item":{"type":"commandExecution","id":"exec-a5f2d12a-619a-43e2-90a8-37f88969840c","command":"/run/current-system/sw/bin/bash -lc 'cat patch-write-marker'","processId":"77919","status":"inProgress","commandActions":[{"type":"read","command":"cat patch-write-marker","name":"patch-write-marker","path":"/tmp/maco-issue77-live.5wNBdc/patch-write-marker"}]}}}
{"method":"item/completed","params":{"item":{"type":"commandExecution","id":"exec-a5f2d12a-619a-43e2-90a8-37f88969840c","status":"completed","aggregatedOutput":"marker\n","exitCode":0}}}
```

Workspace shell write emitted a blocking request. A concurrent filesystem check
while the request was outstanding returned `marker=absent`; declining produced
an item with status `declined` and the marker remained absent.

```json
{"method":"item/started","params":{"item":{"type":"commandExecution","id":"exec-a0e4efcb-e656-4622-a0d8-d80d207b5430","command":"/run/current-system/sw/bin/bash -lc 'touch untrusted-write-marker'","processId":null,"source":"agent","status":"inProgress"}}}
{"method":"item/commandExecution/requestApproval","id":1,"params":{"threadId":"019ffea0-8fe0-7eb2-8a91-b0afe9b841f9","turnId":"019ffea1-3dd0-7ac1-bcc0-9bcadf6410fb","itemId":"exec-a0e4efcb-e656-4622-a0d8-d80d207b5430","command":"/run/current-system/sw/bin/bash -lc 'touch untrusted-write-marker'","cwd":"/tmp/maco-issue77-live.5wNBdc"}}
marker=absent
{"id":1,"result":{"decision":"decline"}}
```

Workspace patch emitted a blocking request. A concurrent filesystem check while
the request was outstanding returned `marker=absent`; declining produced an
item with status `declined` and the marker remained absent.

```json
{"method":"item/started","params":{"item":{"type":"fileChange","id":"exec-f5ec7009-d795-4591-9162-a7656bc2cc5e","changes":[{"path":"/tmp/maco-issue77-live.5wNBdc/untrusted-patch-marker","kind":{"type":"add"},"diff":"marker\n"}],"status":"inProgress"}}}
{"method":"item/fileChange/requestApproval","id":2,"params":{"threadId":"019ffea0-8fe0-7eb2-8a91-b0afe9b841f9","turnId":"019ffea2-3844-7542-a268-dc7223ad8454","itemId":"exec-f5ec7009-d795-4591-9162-a7656bc2cc5e","reason":null,"grantRoot":null}}
marker=absent
{"id":2,"result":{"decision":"decline"}}
```

## MCP shape

An ambient probe-only MCP tool used a different blocking server request shape.
The tool did not execute after the client declined:

```json
{"method":"item/started","params":{"item":{"type":"mcpToolCall","id":"exec-a3575d6d-bd0b-498f-9a49-17c28f1ba3f6","server":"bm25_code_search","tool":"search","status":"inProgress","arguments":{"query":"definitely_absent_issue77_probe"}}}}
{"method":"mcpServer/elicitation/request","id":0,"params":{"threadId":"019ffe9b-b695-7a90-b6a8-c6e2a5f552f0","turnId":"019ffe9e-b7c8-79c0-bd01-a84796effb36","serverName":"bm25_code_search","mode":"form","_meta":{"codex_approval_kind":"mcp_tool_call"}}}
{"id":0,"result":{"action":"decline"}}
{"method":"item/completed","params":{"item":{"type":"mcpToolCall","id":"exec-a3575d6d-bd0b-498f-9a49-17c28f1ba3f6","status":"failed","error":{"message":"user rejected MCP tool call"}}}}
```

Production MACO launches with a private `CODEX_HOME`, empty dynamic tools, and
apps/plugins/hooks/browser/image features disabled. It therefore does not rely
on this MCP path. The protocol still cannot make all MCP tools ask: upstream
approval logic returns without prompting when tool annotations/mode do not
require approval.

## Conclusion

`untrusted` provides blocking client requests for the observed write and patch
classes, but known-safe reads still execute without a callback. `on-request`
also allows ordinary writes, patches, destructive commands, and network
attempts to bypass. Codex 0.144.4 therefore cannot satisfy MACO's universal
pre-action-review contract, and writable production launch must remain closed.
