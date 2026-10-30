# Code Assist wire observation unit

`gemini_code_assist_wire.mjs` observes raw Code Assist responses for Gemini CLI
0.41.2 and Node 22.22.2. The managed bootstrap imports it into a source-bound,
contained process with a private supervisor channel. Standalone callbacks and
snapshots are structural observations, not authenticated custody or authority.

## Pinned source

The packaged `chunk-ZP3RCUP6.js` SHA256 is
`2caaf0808ed644ec464f4ac8c3298dfaa48a0b094578f72a1193c31a19cd847c`.
Relevant original source ranges are 273743–273831 (CodeAssist request methods),
251829–251842 (raw response projection), 10745–10791 (OAuth request/replay),
10106–10175 (DefaultTransporter), 8770–8840 and 8989–9013 (Gaxios), and
8199–8288 (retry configuration). Supported finish reasons are pinned in
`chunk-XRLFHCHC.js`, SHA256
`212695ba37862c484ca6a0617e52715b5338754a6e9fbc3733facad82db411e4`,
lines 26825–26842. Vendor files remain read-only.

## Capture contract

Every physical request needs fresh admission and release ACKs, including OAuth
replays. Generation responses pass through strict bounded UTF-8/SSE/JSON parsing
before CLI translation or logging. Duplicate keys, malformed/trailing frames,
empty streams, missing terminal candidates, unsafe/regressing counters and
conflicting model fields refuse. The original OAuth/Gaxios methods retain their
receivers; redirects and hidden retries are disabled on every physical send.
Unclassified sends refuse. Bootstrap account/startup traffic has its own bounded
non-generation handling and never becomes generation usage.

`usageSnapshotComplete` records whether the latest response envelope explicitly
contained all six native usage counters. It is reset on a missing or partial
later envelope, even when retained counters still contain every key. It does
not independently assert invocation completeness. The Rust private receiver
requires clean terminal attempts, complete final snapshots, observed model and
bound launch identity before admitting complete accounting or publication.
Missing counters are never defaulted to zero, and missing modelVersion is never
replaced by request.model. No served effort field is exposed by the pinned
response projection; `actualEffort` remains null.

Retained snapshots are monotonic lower bounds and are not added within one
attempt. Stream loss, failure, cancellation or early return preserves available
facts but cannot prove complete usage. Standalone records retain
`usageCoverage=observed_lower_bound_only`, `qualified=false`, unknown cost and
unproven quiescence. Only the separate authenticated parent bridge can establish
the whole-invocation contract described in `gemini_managed_bootstrap.md`.

ACK failure latches cancellation, including queued calls. Idle stream aborts
finalize a released attempt without waiting for another consumer operation;
terminal delivery is bounded and idempotent. This does not prove a provider stop.
No headers, credentials, prompts, candidate text, raw response bodies or raw
exception messages cross the observation interface.

Bounds are 64 calls, 128 physical attempts, 4 MiB/response, 64 KiB/SSE frame,
4096 frames and 5 seconds/ACK. Overrides may only reduce these bounds.

## Offline verification

Use Node 22.22.2 with
`node --test src/runtime_adapter/gemini_code_assist_wire.test.mjs`.
Set `MACO_CODE_ASSIST_PUBLIC_SOURCE` to the installed pinned bundle for the
required source-binding test. Synthetic streams and callbacks require no
network, credentials or provider calls and are not real route qualification.
