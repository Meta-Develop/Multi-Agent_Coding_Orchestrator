# Code Assist wire observation unit (not a launch route)

`gemini_code_assist_wire.mjs` is an isolated, version-bound foundation for Gemini
CLI **0.41.2**, Node **22.22.2**. No Rust adapter imports it. Existing Gemini
`Unverified` confinement, `UsageReporting::None`, terminal JSON observation,
acceptance and publication gates remain unchanged. Pure callback facts are not
private parent custody, actual model/effort identity, whole-run usage, price or
writable-execution proof.

## Bound public source

The packaged `chunk-ZP3RCUP6.js` SHA256 is
`2caaf0808ed644ec464f4ac8c3298dfaa48a0b094578f72a1193c31a19cd847c`.
Relevant original line ranges:

- 273743–273831: `CodeAssistServer.requestPost/requestStreamingPost` and the
  permissive stock SSE decoder replaced at these instance method slots.
- 251832–251845: raw `{response: {usageMetadata, modelVersion, candidates}}`
  projection by `fromGenerateContentResponse`.
- 10745–10791: OAuth `request/requestAsync`, including 401/403 replay through
  `this.transporter.request` after refresh.
- 10106–10175: `DefaultTransporter`, its `instance` Gaxios and original receiver.
- 8770–8840, 8989–9013: Gaxios request, adapter, response parsing and defaults.
- 8199–8288: retry configuration; **`retry: false` alone is insufficient when
  `retryConfig` exists**. Every observed send replaces it with retry=0 and
  noResponseRetries=0. Nonempty defaults/interceptors and changed known methods
  refuse; HTTP redirects are disabled because they could resend below admission.

`chunk-XRLFHCHC.js` SHA256 is
`212695ba37862c484ca6a0617e52715b5338754a6e9fbc3733facad82db411e4`.
Its lines 26825–26842 define the supported native candidate finish reasons.

## Interface and limitations

`createCodeAssistWireUnit({parent, limits})` exposes `request`, `wrapTransport`,
`cancel` and `snapshot` for a future owned bootstrap and pure offline tests.
The parent callbacks `admit(event)` and `record(event)` must return exactly
`true`. Each physical generation send, including an OAuth replay, needs fresh
admission and a release-record ACK. Every parsed envelope is captured and ACKed
before downstream delivery. Terminals reconcile once per attempt. A failed ACK,
malformed stream, cancellation or early consumer return latches refusal for
queued/new calls. Already released generation may still consume unreported
usage; ACK backpressure is not a provider spending guarantee.

Owned-signal abort also finalizes a released **idle** stream before its first
read or between reads, independently of later consumer `next`/`return` calls.
The same idempotent terminal promise serves abort, iteration and return. Its
bounded ACK completion unregisters the call even if the ACK fails; snapshots
distinguish pending/acknowledged/failed terminal delivery and expose active call
count. Source cleanup is requested without waiting on an uncooperative iterator.
Retained usage, unknown cost and unproven quiescence are unchanged by this local
terminal transition; it is not a provider stop or whole-run settlement proof.

`attachCodeAssist0412(server, unit, sourceBytes)` requires the exact public bundle
bytes and known function-source fingerprints before modifying the supplied
instance. It preserves original client/transporter receivers, uses the OAuth
client normally and interposes every generation call through its transporter.
Unary responses also request raw streams, avoiding Gaxios's prior JSON parsing
and unbounded text buffering. Unknown clients/transports, custom defaults,
interceptors, endpoints, extra credit enablement and non-generation sends refuse.
In particular credential-refresh network requests are **not authorized here**:
the offline replay tests model the OAuth control path, not a real refresh. Later
bootstrap/profile work must explicitly own any allowed non-generation activity;
it must not bypass this refusal or turn it into generation completeness.

The future loader must bind the supplied source bytes to the actual imported
module, cover every generator/auth-refresh instance before use, and isolate
untrusted code. Fingerprints are compatibility checks, not a sandbox against
arbitrary in-process JavaScript. This unit never imports vendor modules or main,
loads credentials, creates a process/profile/pipe, or calls a provider itself.
An unsupported installation is refused rather than replaced with a generic
transport fallback. Actual installation into the packaged CLI remains untested.

Strict UTF-8/SSE/JSON handling rejects duplicate keys, malformed/trailing frames,
empty streams and streams missing a terminal candidate. It supports one candidate.
A clean stream cannot prove absence of a lost intermediate frame: output is always
`observed_lower_bound_only`, `qualified=false`, with unknown cost and actual effort.
Native usage counters retain their names and are never translated into invented
token sums. Repeated/cumulative snapshots are not added; distinct attempts stay
separate. Missing counters/identity remain unknown, valid previous observations
survive later failure, and unsafe or regressing counters refuse. `modelVersion`
is an unverified response field, never a requested-label substitution. Evidence
contains only bounded whitelisted fields and envelope hashes, not headers,
credentials, prompts, candidate text, raw bodies or exception messages.

Agent-chosen local bounds (not owner budgets): 64 calls, 128 physical attempts,
4 MiB/response, 64 KiB/SSE frame, 4096 frames, 5 seconds/parent ACK. Overrides may
only reduce these bounds. An in-flight or non-cooperative source can remain
unquiesced after cancellation; records explicitly retain `quiescence=unproven`.
No record permits refund, cleanup, settlement or acceptance in MACO.

## Offline verification

Use Node 22.22.2 and `node --test src/runtime_adapter/gemini_code_assist_wire.test.mjs`.
Set `MACO_CODE_ASSIST_PUBLIC_SOURCE` to the already installed public bundle above.
The binding test reads and hashes text only; it does not import/execute the CLI.
Tests use synthetic streams and callbacks, no network, auth or live fixture.
No Cargo build is needed because Rust sources and launch integration are untouched.
