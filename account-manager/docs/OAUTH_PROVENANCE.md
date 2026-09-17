# Gemini OAuth implementation and provenance

The MACO import starts from Coding Agent Manager commit
`953f37ed77c302f9624854c0fbdf2811e70d9fd0`. That snapshot's `NOTICE` and
`src-tauri/src/providers/gemini_oauth.rs` attribute the previous loopback and
token-exchange implementation to Antigravity-Manager. The original module was
excluded from this import. Its replacement and protocol tests are independently
written from the first-party facts below; Antigravity-Manager implementation
code was not used. The historical notice remains available in `NOTICE`.

The remaining application keeps its GPL-3.0-or-later license. This document
records implementation provenance and compatibility facts; it does not assert
that another project's license has changed.

## Protocol facts

- Google's [installed-application OAuth protocol][google-oauth] defines the
  authorization and token endpoints, authorization-code exchange, offline
  credentials, loopback redirects, and PKCE parameters.
- [RFC 8252][native-apps] requires an external user agent and PKCE for public
  native clients. The listener uses an operating-system-assigned loopback port;
  it never binds a public interface or accepts an operator-supplied callback URL.
- [RFC 7636][pkce] defines the S256 calculation. The implementation creates a
  fresh 32-byte random verifier and a separate random state for each operation.
  Its test uses the RFC's published S256 interoperability vector.
- Google's Gemini CLI at [revision `571851b`][vendor-oauth] supplies the public
  installed-application client identifiers, scopes, `/oauth2callback` path, and
  five-minute browser-login deadline. The application uses those configuration
  facts without copying the vendor's implementation. The public client secret
  identifies an installed application; it is not an account credential.
- The vendor's [storage paths][vendor-storage] and [account metadata
  schema][vendor-accounts] define the managed `.gemini` documents. Expiry uses
  Unix milliseconds. The account file contains `active` and `old` fields.

The replacement retains CAM's 8,192-byte callback admission bound and applies
that bound to OAuth response payloads. The five-minute deadline covers the
browser handoff, callback, exchange, and identity request. These are local
operation bounds, not claims about Google's token expiry or service limits.

The system browser is explicitly handed off to a child reaper. In particular,
[`xdg-open` may remain running for the application's lifetime][xdg-open]; the
callback therefore progresses independently of launcher exit. Spawn failures and
early unsuccessful exits are reported. Login cancellation closes its listener
and request waits, but never kills the user's external browser. This handoff
does not apply to managed coding-agent execution.

## Account and failure boundaries

Only an explicit provision operation opens the system browser. The account
adapter continues to require an unselected pending record with a derived managed
home. This module neither selects an account nor schedules refresh; the launched
Gemini CLI owns refresh of its own credentials.

The callback must use the exact host, path, HTTP method, and unpredictable state.
Duplicate security parameters, conflicting code/error outcomes, malformed frames,
and mismatched state are refused. Codes, tokens, identity responses, and raw
upstream errors are absent from diagnostics. Production endpoints are fixed;
the private function parameters used by synthetic transport tests are not IPC
or configuration options. Redirects and token-request retries are disabled.

The token response is validated before credential writes. The module writes
valid managed settings and account metadata before `oauth_creds.json`, which is
the existing account adapter's recovery marker. Companion failure restores prior
documents and leaves that marker absent. A failure after the credential rename
retains both valid companions, allowing existing registry recovery to validate
the account without another authorization-code exchange. Settings updates retain
unrelated keys. Existing credentials cannot be overwritten by a new provisioning
call.

Writes use the application's existing private, atomic filesystem helper. The
live tool home and application data-directory identity are unchanged. This does
not add a transaction with external processes modifying the same managed home;
the existing security model's filesystem race boundary still applies.

Synthetic tests cover callback frames and real loopback sockets, the PKCE vector,
the exact token request, redirects and invalid responses, credential-marker
ordering, settings restoration, and recovery after a post-rename failure. They
also prove that a long-lived opener does not block a callback or get killed by
login cancellation; each synthetic opener is released and reaped by its fixture.
Tests use no real login or account. Real vendor acceptance remains a separate manual
validation step.

[google-oauth]: https://developers.google.com/identity/protocols/oauth2/native-app
[native-apps]: https://www.rfc-editor.org/rfc/rfc8252.html
[pkce]: https://www.rfc-editor.org/rfc/rfc7636.html
[vendor-oauth]: https://github.com/google-gemini/gemini-cli/blob/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/code_assist/oauth2.ts
[vendor-storage]: https://github.com/google-gemini/gemini-cli/blob/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/config/storage.ts
[vendor-accounts]: https://github.com/google-gemini/gemini-cli/blob/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/utils/userAccountManager.ts
[xdg-open]: https://manpages.debian.org/unstable/xdg-utils/xdg-open.1.en.html
