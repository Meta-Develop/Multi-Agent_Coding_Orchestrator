# Gemini managed bootstrap

The managed route pins Gemini CLI 0.41.2 and Node 22.22.2. The supervisor launches
Node directly, verifies the imported package closure and its in-memory guard
transformations, and authenticates a private Unix socket to the contained PID,
process start identity and guardian cgroup. Nonce, sequence and acknowledged
messages bind the closure, physical requests, native tools and final result.
Serialized reports and worker-written logs cannot restore this live custody.
Static adapter capabilities and terminal JSON observation grant no authority.

The online route requires the selected personal OAuth account and a finite live
token grant. Read-only roles admit native ReadFileTool; the managed terminal
Worker additionally admits WriteFileTool and EditTool with a held native journal.
Shell, native delegation, MCP, extensions, hooks and arbitrary external I/O remain
denied. Managed write completion requires an observed native mutation, a bound
result, successful contained execution and verified process/scratch cleanup.
Primary-worktree publication and independent acceptance retain their own gates.

## Usage and served identity

The wire observer captures Code Assist response envelopes before the pinned
CLI projects them into telemetry. Package `chunk-ZP3RCUP6.js` projects raw
`response.usageMetadata` and `response.modelVersion` at lines 251829–251842.
Its logging paths at 274484 and 274605 can fall back to the requested model;
its ApiResponseEvent constructor at 243467–243473 defaults absent counters to
zero. Neither terminal telemetry nor these fallback/default values are used
for authenticated settlement.

Every admitted generation attempt must reach clean EOF with an observed model
and a final snapshot explicitly containing prompt, candidates, total, cached,
thoughts and tool-use prompt counters. Even optional missing counters remain
unknown. A union of partial frames does not establish a complete final snapshot.
Snapshots within an attempt overlap; distinct attempts are summed with checked
arithmetic. Startup/authentication requests must also be terminal. Interrupted,
missing, partial, unsafe, regressing or overflowing observations cannot establish
complete invocation accounting. Known total-token lower bounds survive failure.

The parent retains all six native buckets. Input combines prompt and tool-use
prompt tokens; output combines candidates and thoughts. Cached input is already
included in prompt and is never added again. Each attempt and its aggregate
must agree with the observed total using checked arithmetic; inconsistent
metadata cannot establish complete accounting. No missing bucket becomes zero.
These bucket meanings follow the [provider UsageMetadata contract](https://googleapis.github.io/js-genai/release_docs/interfaces/types.UsageMetadata.html);
the pinned source projects those raw fields unchanged.

Completion requires the observed model to equal the exact selected model.
Missing modelVersion and fallback/multiple-model responses cannot satisfy that
gate. A complete mismatched-model observation can retain accounting and its
actual model label, while publication fails. The response projection exposes
no served effort; actual effort remains unknown and a requested effort cannot
qualify completion. Requested configuration is never reported as served effort.

Supervised settlement reports complete private input/output/total usage and the
observed model. Only successful, safe, identity-matching completion settles as
reliable. Other released runs retain estimated lower bounds or missing usage.
No-release refund still requires verified quiescence. Provider prices, USD cost
and subscription quota conversion remain unknown; no prices are synthesized.
The standalone consultation path continues conservative lower-bound settlement.

## Verification and remaining gates

Rust receiver tests exercise complete distinct attempts, missing/partial usage,
model fallback/mismatch, unknown effort, forged terminal claims, worker logs,
report round trips, reporting and ledger settlement. The wire tests use synthetic
unary/SSE streams and test partial final snapshots independently of retained
counters. Existing native-journal, read-only, closure, admission, grant breach
and cleanup checks remain applicable.

Run `node --test src/runtime_adapter/gemini_code_assist_wire.test.mjs` with Node
22.22.2. The source-binding case requires `MACO_CODE_ASSIST_PUBLIC_SOURCE`
pointing to the installed pinned bundle; it reads/hashes text without executing
vendor code. Installed-module bootstrap tests require their documented isolated
namespace prerequisites. No synthetic test establishes real provider acceptance.

Real route qualification still requires the exact selected account, compatible
model catalog/prior, complete provider metadata, substantive confined edits,
independent acceptance, retained receipts and verified cleanup. This source
contract does not grant provider-call or publication authority by itself.
