# Claude Code served identity

The managed Claude Code route pins version **2.1.137** and executable SHA256
`404ef447ddea09867ba29f6c5aecccafd3951b6fd6021f118a49295bbae90238`.
Its native `stream-json` protocol exposes the API response model in
`stream_event.event.message.model` on `message_start`. The collector retains
that model per message, checks consistency with assistant messages and result
`modelUsage`, and reconciles it against the parent broker's captured API
responses. Managed ReadWrite child publication additionally requires an exact
match with the launch's requested model; missing or conflicting response
models are refused.

Source inspection of this executable's embedded JavaScript establishes:

- The `UX8` init emitter and init schema emit `model`, but no effort. The init
  model is client configuration, not a replacement for the API response model.
- The result schemas emit `usage` and `modelUsage`, but no served effort.
- The partial-message emitter forwards API events into `stream_event.event`.
  Neither that wrapper nor the inspected response handling provides a
  served-effort observation.
- Request `output_config.effort`, `--effort`, and hook `effort.level` concern
  client-side selection/application. They do not attest backend served effort.

`ClaudeNativeEvidence.observed_effort = None` explicitly means **unknown**.
The pinned collector always produces that state, including when an
unrecognized effort field appears in captured JSON. It never copies a requested
effort, an init claim, a hook value or a request parameter into served evidence.
Any future observation source requires a separate source-bound implementation
and qualification; adding a field to a synthetic receipt cannot qualify it.

Owner policy dated 2026-11-02 permits Managed ReadWrite child publication
with a matching served model and exact launch-bound requested effort when
served effort is absent. Reports retain a null effort observation and record
`effort_basis: requested`. Requested effort is not a served-effort claim.
A provider-reported contradiction still refuses. Missing/mismatched served
model, missing whole-call usage, launch drift, confinement, command journal,
independent review, acceptance and publication restrictions remain unchanged.
ReadOnly auditors preserve their existing usage and model gates.

Complete witnessed usage still settles as Reliable independently of an identity
refusal. Substantive selected-account Linux execution and independent acceptance
remain live-only requirements in #693; this source policy does not qualify them.

Providerless regressions cover missing and mismatched response models,
unrecognized/missing effort, and a synthetic mismatched observed effort at the
identity matcher and publication check. Synthetic matcher values are test
inputs, not observations from this executable. No live provider acceptance or
credential availability is established by those tests.
