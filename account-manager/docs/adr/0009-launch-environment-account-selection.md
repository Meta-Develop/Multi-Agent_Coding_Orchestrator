# 0009. Launch-environment account selection

- **Status**: Proposed
- **Date**: 2026-08-20

## Context

Some managed tools choose credentials from the environment of the process that
starts them rather than from an account pointer in a shared config file. Gemini
CLI accepts a Developer API key through `GEMINI_API_KEY`. Isolated Google OAuth
uses `GEMINI_CLI_HOME`. Grok CLI resolves its home through `GROK_HOME`, so a
vendor-written home can remain in place while an application-launched process
selects it.

Treating these providers as file-switch adapters would create unnecessary
credential copies and race vendor refreshes. Mutating this application's
process environment would be global, racy, and unable to affect tools launched
outside it. Passing a secret or executable path through webview IPC would move
privileged launch decisions across the wrong trust boundary.

The account lifecycle also crosses two durable systems: non-secret metadata and
either `CredentialStore` material or a vendor-written home. An interrupted add
or delete must remain recognizable and recoverable. A selected account must not
be usable until both its metadata and external material are complete.

The provider research supporting these paths uses `[verified-source]` for facts
observed in first-party source at an immutable revision with exact citations.
That marker does not prove that a locally installed binary matches the source.
It also does not change [ADR 0007](0007-reading-other-implementations.md): source
from a third-party implementation remains a hypothesis about the managed tool,
not vendor evidence.

## Decision

### Activation and launch

An adapter may declare `LaunchEnvironment` as its activation mechanism.
Activation then persists only the selected account id in non-secret metadata.
It does not mutate the application process environment or a managed tool's
config.

The adapter declares a complete launch specification: a fixed program, fixed
arguments, an exact absolute working directory, and the exact environment
entries to set or remove. These values come from compiled adapter logic and
derived account paths, never from an arbitrary program, argument, path, or
environment map supplied over IPC or persisted in account metadata.

Core alone constructs and spawns the child. It applies the adapter declaration
only to that child. A tool started from another shell, desktop entry, editor, or
process remains unaffected. Process-global environment mutation is forbidden.

Selection is validated twice. Before persisting a new selection, core validates
the current selected account, when it differs, and the target account. Before a
launch, core validates the selected account again. This narrows, but cannot
eliminate, the time-of-check/time-of-use window created by external processes.
Adapters fail closed when a conflicting state is knowable.

### Secret boundary

Credential references are derived inside Rust core from `(provider_id,
account_id)`. They are not accepted from IPC and are not persisted in account
metadata. Core resolves a selected credential through `CredentialStore` only
immediately before spawn. The value is applied only to the declared child
environment variable.

A secret never appears in IPC, account metadata, a launch result, a log, an
error, or diagnostic output. Launch results contain only non-secret process and
account identifiers. Adapter launch specifications carry no secret values and
are not serializable IPC types.

The child process necessarily receives the secret. Depending on the operating
system, another process running as the same user may be able to inspect the
child's environment or memory. This is a residual platform risk, not a reason
to broaden the secret boundary. The application minimizes exposure by avoiding
process-global mutation, resolving at spawn time, and never capturing child
stdio.

### Stored-account lifecycle

Persist only non-secret account metadata: id, label, provider, auth kind,
material class, lifecycle state, and selection state. The lifecycle states are
`Pending`, `Complete`, and `Deleting`. The material classes are
`CredentialStore` and `VendorHome`.

An add writes `Pending` metadata before provisioning external material and
changes it to `Complete` only after provisioning succeeds. A delete first runs
the provider's read-only validation and refusal gate. Only after that succeeds
does core change the account to `Deleting` and clear its selection.
Credential-backed deletion calls `CredentialStore::delete` before removing
metadata. Vendor-home deletion forgets metadata but retains the home. Recovery
deletes incomplete credential-store material idempotently. It preserves a
pending vendor home for provider-specific inspection rather than guessing
whether vendor login completed.

Only a `Complete` account may be selected or launched. `Pending` and `Deleting`
records remain visible recovery state, not usable accounts.

### Gemini CLI

Gemini API-key accounts use `CredentialStore` material. Core injects the
selected value as `GEMINI_API_KEY` only into the launched Gemini process.

The adapter evaluates the effective Gemini settings for the exact launch
working directory before selection and again before launch. It accounts for the
user, trusted-workspace, system-default, and system settings merge; the system
settings path override; configured `security.auth.selectedType` taking
precedence over environment detection; the documented environment detection
order; and `security.auth.enforcedType` mismatch refusal. It refuses unless the
effective result permits Gemini Developer API-key authentication.

Activation and launch do not write Gemini config. The Gemini config tree must
be byte-identical before and after activation. An already-set child environment
value is not replaced by Gemini's dotenv loading. Because no managed-tool file
is replaced, this selection requires no config backup.

Gemini OAuth accounts use `VendorHome` material. Add writes an isolated
`GEMINI_CLI_HOME` containing `oauth_creds.json`, `google_accounts.json`, and
managed `settings.json` with `security.auth.selectedType` set to
`oauth-personal`. Launch sets that home and `GOOGLE_GENAI_USE_GCA=true` on the
child. This path does not write or swap the live `~/.gemini` tree. Listing may
include a read-only on-disk OAuth row when live `oauth_creds.json` is present.

### Grok CLI

Grok accounts use `VendorHome` material at the derived path
`{data_dir}/accounts/grok-cli/{account_id}`. The manager creates the home, and
the vendor tool creates and writes its credential state. Selection persists
only metadata, and core launches Grok with `GROK_HOME` set to the derived home.
An inherited `GROK_AUTH_PATH` that could bypass the selected home is removed
for the child.

The manager never copies, restores, rewrites, backs up, or deletes Grok
`auth.json`, and never interprets, extracts, or logs credential values from it.
It may validate that the file is a regular top-level JSON object; any input
buffer used for that check is transient and zeroized. Before selection, the
adapter checks the real vendor auth lock and active-session state for both the
current and target homes. It repeats the applicable lock and session checks
immediately before launch. A held lock, active session, unreadable gate, or
ambiguous state causes refusal.

Deletion forgets the metadata but retains the vendor home and its
vendor-written files. The user must deliberately remove a retained home outside
the account-forget operation if destruction is intended.

### Backup boundary

`NFR-4` applies when this application replaces a file belonging to a managed
tool. Pure selection changes only application-owned non-secret metadata and a
future child environment, so it does not trigger a managed-config backup.
Metadata writes remain atomic and lifecycle-journaled.

Any future operation that mutates a managed tool's config still requires a
restorable timestamped backup before the first write. This decision creates no
general exception to `NFR-4`.

## Consequences

- Gemini API keys stay in `CredentialStore` until the selected child is
  spawned; the webview never receives them.
- Grok homes stay in the format and location in which the vendor wrote them.
  The application gains a narrow plaintext secret surface without learning or
  copying the credential schema.
- Selection affects only application-launched processes. UI wording must not
  claim that an external shell or editor changed accounts.
- Exact working-directory selection is security-relevant because Gemini
  workspace settings participate in the effective auth mode.
- A same-user process may inspect a launched child's environment. Users who do
  not accept that operating-system boundary must not use environment-injected
  API-key launch.
- External-process races remain possible between validation and spawn. Recheck
  and fail-closed gates reduce the window but cannot provide a cross-process
  transaction.
- Forgetting a Grok account intentionally leaves its vendor home on disk. The
  UI and diagnostics must distinguish forgotten metadata from destroyed
  credential material.
- Metadata-only activation does not create backups. Grok homes are not copied
  into the backup store under this design.

## Alternatives considered

- **Mutate the application process environment.** Rejected because it is racy
  across concurrent launches, leaks selection into unrelated children, and
  cannot affect a tool started outside the application.
- **Send secrets through IPC for the webview to launch the tool.** Rejected
  because it makes an XSS bug a credential-read primitive and violates
  `NFR-1`.
- **Accept arbitrary programs, arguments, working directories, or environment
  maps from IPC or account metadata.** Rejected because account selection is
  not a general command-execution interface.
- **Copy or restore vendor auth files during activation.** Rejected because it
  creates credential copies, races vendor refresh, and is unnecessary for
  providers with verified launch-environment selection.
- **Hold Grok's vendor auth lock for the child's entire lifetime.** Rejected
  because the lock belongs to the vendor's short credential transactions. A
  lifetime hold would interfere with refresh and vendor stale-lock recovery.
- **Delete a Grok vendor home when metadata is deleted.** Rejected because it
  is destructive, can race an external process, and cannot be recovered from
  the metadata transaction.
