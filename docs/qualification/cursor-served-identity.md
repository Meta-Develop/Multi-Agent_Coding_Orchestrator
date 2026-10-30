# Cursor served identity gate

The managed route is bound to Cursor CLI `2026.04.08-a41fba1` and the entry
and chunk digests in `src/runtime_adapter/cursor/managed_bridge.rs`. Source
inspection of that exact installed package establishes the following limits;
it does not qualify a real execution or prove provider-side behavior.

The lower `AgentClient` call consumes `AgentServerMessage` before ACP projects
its output. Its six response variants are `interactionUpdate`,
`execServerMessage`, `execServerControlMessage`,
`conversationCheckpointUpdate`, `kvServerMessage`, and `interactionQuery`.
`InteractionUpdate` has no served-model or served-effort variant.
`TurnEndedUpdate` has four optional token counters: `input_tokens`,
`output_tokens`, `cache_read_tokens`, and `cache_write_tokens`. It has no
model or effort field. The parent retains these counters independently of
identity completeness.

`ModelDetails` and `RequestedModel` are request-side selection. The ACP chunk's
`currentModelId` comes from `resolveSelectedAcpModelVariantId`, and the model
manager's `buildRequestedModel` uses its current selection and parameters.
These values cannot establish which model or effort served a response.
`ThinkingDetails` has an empty field list. Optional `model` fields in hook
requests describe hook context, with no corresponding served-effort field or
whole-invocation identity contract; hooks remain denied on this route.
Opaque checkpoint/KV content and generated text are not identity witnesses.
The source forwards an optional `onHeader` callback, but supplies no defined
served-model/effort header contract that this route can authenticate.

Consequently `actualProviderModel` and `actualEffort` remain explicitly `null`
in the bridge envelope and parent evidence for this pin. The parent rejects
non-null identity claims in that envelope and never promotes identity claims
inside generated text, reports, or extra raw fields. Complete usage alone
cannot make the result publishable. Publication requires nonempty selected
and independently observed served model and effort, with exact matches.
Omitting selection does not waive that requirement.

There is no live command or flag that closes this identity gap on the admitted
contract. Before substantive qualification, a future source-bound contract
must expose authoritative served model and effort for every admitted attempt,
retain them through the private parent transport, and reject missing,
conflicting, mismatched, or output-forged identities. Such a change must update
the relevant source pins and pass independent review. Do not run a paid
qualification merely to rediscover this source-level refusal.

Deterministic coverage is in `managed_bridge.test.cjs`, the
`runtime_adapter::cursor_managed_parent::tests` module, and
`external_agent::tests::cursor_client_selection_is_not_actual_provider_identity`.
The bridge source and its vendor digests are unchanged by this gate hardening.
