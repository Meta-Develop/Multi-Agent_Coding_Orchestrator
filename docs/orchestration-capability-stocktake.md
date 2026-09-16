# Orchestration capability stocktake

Public reconciliation of Multi-Agent Coding Orchestrator (MACO) orchestration behavior against named competitor frameworks, for [issue #94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94). This document is product and source documentation only; it does not close issues or claim universal parity.

**MACO source baseline:** commit [`0bf93dcca9ddc4f7fb42ae3c1be8b07dc7503710`](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/commit/0bf93dcca9ddc4f7fb42ae3c1be8b07dc7503710) (retrieval **2026-09-17**). Upstream competitor citations use mechanism-specific documentation retrieved **2026-09-17** unless a pinned commit is noted in text.

**Umbrella status:** [#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94) remains open. The original acceptance set—[#26](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/26), [#90](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/90), [#149](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/149), [#408](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/408), [#409](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/409), [#410](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/410)—also remains open. Unmerged candidate [PR #434](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/pull/434) (`f288086`) is not merged acceptance here.

---

## Method

Each mechanism is classified in three layers:

| Layer | Meaning |
|--------|---------|
| **Implemented library** | Types, reducers, journals, or adapters exist in the Rust tree and are covered by unit or integration tests. |
| **Production-connected** | A documented CLI or supervise/orchestrate path invokes the mechanism during real runs (not test-only hooks). |
| **Demonstrated external acceptance** | Publishable run artifacts, forge receipts, held-out experiments, or production review loops prove the behavior under MACO’s integrity model. |

[#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94) requires analyzing and absorbing named competitor capabilities; every gap row below states what is missing or unverified and what evidence would satisfy acceptance before umbrella closure. Competitor-specific transports (remote sandboxes, federation links, agent servers) remain in scope until connected and accepted under the same three layers.

---

## Cross-cutting MACO behavior (baseline `0bf93dc`)

Credible on the pinned tree; not a claim that [#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94) is complete.

**Static plan DAG and parallel waves.** JSON orchestration plans use acyclic `depends_on`; `maco orchestrate run` schedules ready agents with claim-aware concurrency ([`../src/orchestrator.rs`](../src/orchestrator.rs), README orchestration sections).

**Authenticated checkpoint resume (orchestrate and supervise).** `maco orchestrate resume` revalidates repository HEAD, plan snapshot, worktree bindings, and completed-agent worktree state; it reruns validation and capture without rerunning completed agent commands (README ~2418–2437; [`../src/orchestrator.rs`](../src/orchestrator.rs)). Supervise resume uses typed denials ([`../src/supervise/plan_api.rs`](../src/supervise/plan_api.rs)); entry via [`../src/cli.rs`](../src/cli.rs).

**Runtime-expanded durable follow-ups.** After publishable licensed-breakage acceptance, MACO materializes `generated_follow_up_tasks`, enqueues them on an authenticated bounded queue, and can resume a cascade ([`../src/supervise/acceptance.rs`](../src/supervise/acceptance.rs), [`../src/supervise/follow_up_cascade.rs`](../src/supervise/follow_up_cascade.rs), [`../src/follow_up_queue.rs`](../src/follow_up_queue.rs)). Orchestrate plan agent cardinality at load remains fixed; expansion lives on the supervise follow-up path. Production dispatch still uses identity-less queue `claim` (see [#332](#foundation-contracts-332335)).

**Initialized messaging broker; child transport not connected.** Every non-empty supervise plan initializes a hierarchy-gated [`MessagingBroker`](../src/messaging.rs) session and durable `messaging.jsonl` ([`../src/supervise/messaging_bridge.rs`](../src/supervise/messaging_bridge.rs), [`../src/supervise.rs`](../src/supervise.rs)). Child IPC remains outside the bridge; production assignments do not publish or receive on governed channels (see [#333](#foundation-contracts-332335)).

**Contained Grok ACP execution.** Grok ACP stdio runs full turns including `session/prompt` under confinement ([`../src/runtime_adapter/grok_acp.rs`](../src/runtime_adapter/grok_acp.rs), [`../src/external_agent.rs`](../src/external_agent.rs)). Parent-authenticated model/effort evidence is bounded separately from execution ([`../src/supervise/acceptance.rs`](../src/supervise/acceptance.rs)).

**Merge arbitration, semantic coordination, role model routing.** External merge arbiter launch ([`../src/merge.rs`](../src/merge.rs)), semantic intent modes ([`../src/semantic_coord.rs`](../src/semantic_coord.rs)), and per-role model selection at assignment launch ([`../src/supervise/assignment_execution.rs`](../src/supervise/assignment_execution.rs)). Automatic routing **mechanism** exists in source; live held-out and outcome-feedback **acceptance** remain on [#26](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/26) and [#149](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/149).

**Checkpoint resume versus replay archive and steering.** Production resume is journal/checkpoint-based. [`execution_replay`](../src/execution_replay.rs) provides bounded public observation-only inspect/replay/fork with disarmed effects ([`../tests/execution_replay.rs`](../tests/execution_replay.rs)); it is not the orchestrate resume path. [`steering`](../src/steering.rs) provides a durable control journal and HTTP serve helpers; production cancel/inject consumers for live external assignments are missing (see [#335](#foundation-contracts-332335)—[`../src/steering/tests.rs`](../src/steering/tests.rs) exercises `SteerableFakeSession` and a rendered Cursor cancellation handle without launching an adapter child through `run_external_agent`).

---

## Foundation contracts ([#332](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/332)–[#335](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/335))

Original acceptance criteria from the foundation issues; status below reflects source at `0bf93dc`. Library credit is preserved where module tests satisfy a criterion; production-connected gaps stay tracked on the same issue numbers under [#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94).

| Issue | Closure vs source | Library complete (module/tests) | Production / acceptance still missing | Evidence that would prove the missing piece |
|--------|-------------------|-----------------------------------|----------------------------------------|---------------------------------------------|
| [#332](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/332) | AC1 graph reducers, AC3 partial fan-in: [`../src/follow_up_queue/graph.rs`](../src/follow_up_queue/graph.rs), tests in [`../src/follow_up_queue.rs`](../src/follow_up_queue.rs). **AC2 + AC4 not met on cascade path.** | `define_graph` / graph transitions / `claim_with_lease` — callers in follow-up queue tests only, not [`../src/supervise/follow_up_cascade.rs`](../src/supervise/follow_up_cascade.rs) | **Required:** licensed-breakage follow-up dispatch must progress items through **lease-bound graph transitions** (not identity-less `claim` at cascade ~247–248); crash/resume must preserve partial sibling success and stale lease reassignment without double subordinate runs | Kill between `claim_with_lease` and ack; `maco supervise` resume cascade via [`../src/supervise/plan_api.rs`](../src/supervise/plan_api.rs) (~3285+); graph replay shows `FanInResult::PartialSuccess` behavior on the **production** consumer |
| [#333](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/333) | AC1 envelopes + at-least-once/ack: [`../src/messaging.rs`](../src/messaging.rs), [`../tests/messaging_protocols.rs`](../tests/messaging_protocols.rs). **AC3 turn policies:** [`../src/messaging/turn.rs`](../src/messaging/turn.rs) with termination/recovery tests in messaging protocols (~1165–1250). AC4 separate from queue records ([`../src/messaging/envelope.rs`](../src/messaging/envelope.rs)). **AC2 not met.** | Session init + resume replay only ([`../src/supervise/messaging_bridge.rs`](../src/supervise/messaging_bridge.rs)); `with_supervisor_messaging_session` is test-only | **Required child transport:** supervisor-launched assignment identities use admitted credentials to publish/receive on governed channels during real `maco supervise` runs (not [`../src/supervise/tests/run_artifacts.rs`](../src/supervise/tests/run_artifacts.rs) factory alone) | Two assignment IDs exchange one envelope; artifact `messaging.jsonl`; resume after crash replays store without credential replacement (bridge ~292–294) |
| [#334](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/334) | **Criteria met at `0bf93dc` (issue remains closed).** AC1–3: [`ExecutionReplayArchive`](../src/execution_replay.rs) inspect/replay/fork with `ReplayBoundaryContract::observation_only` and disarmed effects — [`../tests/execution_replay.rs`](../tests/execution_replay.rs). AC4: uncertain supervise resume refused — [`../src/supervise/plan_api.rs`](../src/supervise/plan_api.rs) (~3993–4018, ~4155–4187); follow-up cascade uncertain source (~3385–3388) | — | Richer competitor parity (LangGraph downstream re-invoke, OpenHands conversation fork, unified transcript export) is **separate [#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94) work** — not grounds to reopen #334 | N/A for #334 closure; competitor analogues need their own acceptance rows under #94 |
| [#335](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/335) | AC3 bounded timeout / no orphan steered state; AC4 steering does not bypass merge — [`../src/steering/tests.rs`](../src/steering/tests.rs), [`../src/steering/plane.rs`](../src/steering/plane.rs). **AC1–AC2 not met in production.** | Fake session cancel/inject tests; Cursor test cancels registered `ProcessCancellation` handle **without** a child launched via [`../src/external_agent.rs`](../src/external_agent.rs) | **Required:** supervise → `run_external_agent` registers assignment on `SteeringPlane`; `CancelAssignment` stops live child (**Fake fixture + one external adapter**); `InjectCorrectiveInput` with `SteeringOutcome::Delivered` in evidence store | Extend writable Grok ACP / fake external patterns in [`../src/external_agent/tests.rs`](../src/external_agent/tests.rs) with steering plane registration—not steering unit tests alone |

---

## Named comparisons

Mechanism-specific upstream docs (retrieval **2026-09-17**). Comparator gaps stay visible until production-connected and demonstrated under the method above.

### [kurone-kito/idd-skill](https://github.com/kurone-kito/idd-skill) (issue-driven coordination)

**Overlap:** Git-centric coordination, path claims, merge freshness, mutation taxonomy, forge-scale multi-host claims—aligned with [#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94) Analysis 1.

**MACO today:** Worktrees, durable sync claims, merge preview/apply gates, inbox repair phases; forge-coordination **library** ([#89](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/89)) in [`../src/publication/forge_coordination.rs`](../src/publication/forge_coordination.rs). Policy foundations [#83](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/83)–[#88](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/88) and [#91](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/91)–[#93](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/93) are implemented as MACO policy/code paths; remaining work is **production connection and live evidence**, not absence of those modules.

**Pending acceptance:** [#410](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/410) forge claim heartbeat/takeover in supervise paths; [#90](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/90) durable PR review loop; [#26](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/26)/[#149](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/149) for held-out routing and outcome feedback in production selection.

### [LangGraph](https://github.com/langchain-ai/langgraph) — [graph API](https://docs.langchain.com/oss/python/langgraph/graph-api), [persistence](https://docs.langchain.com/oss/python/langgraph/persistence), [interrupts](https://docs.langchain.com/oss/python/langgraph/interrupts), [time-travel](https://docs.langchain.com/oss/python/langgraph/use-time-travel)

**Layer distinction:** LangGraph merges in-process graph state with checkpointers and `thread_id`; MACO schedules external agent processes with repo-bound journals and patch bindings.

| Upstream mechanism | MACO analogue | Status |
|--------------------|---------------|--------|
| `State` + reducers / parallel super-step merge | Per-agent artifacts + [`semantic_coord`](../src/semantic_coord.rs) | Missing in-process reducers; partial scheduling only |
| Conditional `Send` / map-reduce | Follow-up queue + cascade resume | Partial runtime expansion; [#332](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/332) graph+lease production consumer missing |
| `interrupt()` / parallel interrupt maps | Gates + steering library | Partial; per-child interrupt resume maps unverified — [#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94) |
| Time-travel fork / `get_state_history` | #334 observation fork + orchestrate/supervise checkpoint resume | #334 closed; LangGraph-style downstream re-invoke and branch history unproven — [#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94) |
| DB checkpointer backends | v3 authenticated journal + MAC/HEAD binding | Different shape; repo/crypto binding via [`../src/state_journal.rs`](../src/state_journal.rs) |

Supervise follow-ups exist; orchestrate/supervise resume revalidates completed agents without command re-exec.

### AutoGen / [AG2](https://github.com/ag2ai/ag2) — [network overview](https://docs.ag2.ai/docs/user-guide/network/overview/), [TransitionGraph migration](https://docs.ag2.ai/docs/user-guide/network/migration_from_group_chat/); [AutoGen Teams](https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/teams.html), [SelectorGroupChat](https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/selector-group-chat.html)

**In tree:** credential registry, governed channels, at-least-once broker ([`../src/messaging.rs`](../src/messaging.rs)); orchestration gate journal ([`../src/orchestration_event.rs`](../src/orchestration_event.rs)); durable turn policies in library ([#333](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/333) AC3).

**Missing / unverified:** AG2 `Hub` / `WsLink` network; workflow `TransitionGraph` routing from tool outcomes; LLM next-speaker selection; supervisor-launched agents on channels ([#333](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/333) AC2).

**Acceptance:** Governed round-trip between two supervise-launched assignments with resume replay; persisted transition graph routes next assignment from recorded gate/tool outcome (distinct from static `depends_on`).

### [OpenHands](https://github.com/OpenHands/OpenHands) — [Agent Server](https://docs.openhands.dev/sdk/arch/agent-server.md), [events](https://docs.openhands.dev/sdk/arch/events.md), [persistence](https://docs.openhands.dev/sdk/guides/convo-persistence.md), [ACP](https://docs.openhands.dev/sdk/guides/agent-acp.md), [fork](https://docs.openhands.dev/sdk/guides/convo-fork.md)

**Partial overlap:** confinement profiles ([`../src/process_runner.rs`](../src/process_runner.rs)), supervise/orchestrate checkpoint resume, typed `ResumeCheckpointDenial` ([`../src/supervise/plan_api.rs`](../src/supervise/plan_api.rs)) — MACO binds resume to repository HEAD, plan snapshot, worktree state, and authenticated journal MAC, not conversation-id alone.

**Missing / unverified:** embedded OpenHands agent loop; first-class Agent Server host; built-in file/terminal/browser tools in MACO core (tools today live in external CLIs); general ACP catalog beyond Grok selector; remote execution backend with MACO artifact contracts; conversation-fork parity (OpenHands `fork()` — track under [#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94), not #334).

**Present:** bounded Grok ACP execution transport (see cross-cutting section).

### [claude-flow / Ruflo](https://github.com/ruvnet/ruflo) — [swarm-tools](https://github.com/ruvnet/ruflo/blob/main/v3/@claude-flow/cli/src/mcp-tools/swarm-tools.ts), [topology-manager](https://github.com/ruvnet/ruflo/blob/main/v3/@claude-flow/swarm/src/topology-manager.ts), [ADR-097 federation budget](https://github.com/ruvnet/ruflo/blob/main/v3/docs/adr/ADR-097-federation-budget-circuit-breaker.md) (upstream pin [`6f0ed711`](https://github.com/ruvnet/ruflo/commit/6f0ed7112873eedc7cfe17281a2585188190b790), 2026-09-16)

**Partial overlap:** hierarchical coordinator roles ([`../src/supervise.rs`](../src/supervise.rs)), swarm-health circuit breaker ([`../src/swarm_health.rs`](../src/swarm_health.rs)), outcome history ([`../src/supervise/outcome_history.rs`](../src/supervise/outcome_history.rs)), messaging library (AG2 section).

**Missing / unverified:** pluggable mesh/ring/adaptive topology products; distributed consensus layers; WSS federation mesh; vector session memory (`.swarm/memory.db` class); production wiring of [#332](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/332) graph dispatch (queue `claim` today, not topology enum alone). Federation hop/budget policies may be ported as invariants when [#410](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/410) connects forge coordination.

### OpenAI [Swarm](https://github.com/openai/swarm/blob/main/README.md) / [Agents SDK handoffs](https://openai.github.io/openai-agents-python/handoffs/), [sessions](https://openai.github.io/openai-agents-python/sessions/), [multi-agent](https://openai.github.io/openai-agents-python/multi_agent/); [Cursor agent-swarm research](https://cursor.com/blog/agent-swarm-model-economics)

**Partial overlap:** durable handoff strings and follow-up plans ([`../src/supervise/acceptance.rs`](../src/supervise/acceptance.rs)), merge arbiter ([`../src/merge.rs`](../src/merge.rs)), field guide ([`../src/field_guide.rs`](../src/field_guide.rs)), role×model binding ([`../src/supervise/assignment_execution.rs`](../src/supervise/assignment_execution.rs)).

**Missing / unverified:** LLM tool handoff / active-agent swap; single chat-loop `client.run`; throughput comparable to Cursor's research VCS; compile-linked design-document reconciliation described in the Cursor article. These mechanisms require comparison and acceptance under [#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94).

**Upstream evidence boundary:** Cursor describes a research harness. Its full N×N planner/worker experiment is future work, not a completed benchmark or an existing product capability. Preserve that distinction when defining comparisons; the article does not establish that the research VCS ships in Cursor's public agent product.

**Acceptance:** [#26](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/26), [#149](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/149) for production model mix; harness-equivalent proof for each Cursor research mechanism absorbed under #94.

---

## Open roadmap (existing issues only)

| Issue | Role |
|-------|------|
| [#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94) | Umbrella; all named comparator mechanisms |
| [#26](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/26) | Held-out / real-runtime validation |
| [#90](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/90) | Production PR review loop |
| [#149](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/149) | Outcome feedback in production selection |
| [#408](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/408) | Delegated WSL / runtime investigation |
| [#409](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/409) | Coding Agent Manager integration |
| [#410](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/410) | Forge coordination in supervise production paths |
| [#332](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/332)–[#335](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/335) | Foundation table above (#334 closed; #332/#333/#335 production gaps) |

---

## Summary judgment

MACO at `0bf93dc` is a local-first, Git-bound, subprocess orchestrator with production checkpoint resume, supervise follow-up expansion, initialized messaging infrastructure, bounded Grok ACP execution, merge arbitration, semantic coordination, and role model routing—plus completed libraries for graph reducers, messaging/turn protocols, observation-only execution replay (#334), and steering control records. It is **not** a demonstrated strict superset of LangGraph, AG2, OpenHands, Ruflo, or in-process swarm SDKs: production consumers for [#332](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/332) graph+leases, [#333](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/333) child messaging transport, [#335](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/335) live external cancel/inject, and the open [#94](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/94) comparator rows above remain to be connected and accepted before umbrella closure.
