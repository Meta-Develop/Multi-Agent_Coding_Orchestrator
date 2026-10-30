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

Managed ReadWrite child publication requires both observed model and observed
effort to match the launch request. Unknown effort therefore fails closed for
every supported effort on this pin, including `high`. Supervisor completion
requires observed effort only for that same parent-recorded launch shape.
ReadOnly auditors retain their complete-usage and observed-model requirements
without inheriting the writable effort gate. This does not provide the
missing whole-call witness for current read-only launches.

Successful exit, valid result text, confinement, and complete token accounting
cannot waive the writable identity gate. An identity-only refusal clears
publication without introducing a process error: verified safety remains true
and complete witnessed usage settles as Reliable. Other process or coverage
failures retain their existing safety and settlement behavior. The contained
launch contract alone does not establish successful writable qualification
for issue #693.

Providerless regressions cover missing and mismatched response models,
unrecognized/missing effort, and a synthetic mismatched observed effort at the
identity matcher and publication check. Synthetic matcher values are test
inputs, not observations from this executable. No live provider acceptance or
credential availability is established by those tests. Until a qualified
served-effort source exists, no live command on this pin can satisfy the full
observed-identity acceptance requirement.
