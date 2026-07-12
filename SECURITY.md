# Security policy

## Execution boundary

MACO treats provider-proposed commands, validators, external reviewers, and external model
processes as untrusted. A result is publishable only when two independent facts are proven:

1. the owned process tree is empty at return; and
2. the requested side-effect profile was applied and verified before the target start gate opened.

An exit status, a model attestation, or a best-effort process group is not safety evidence.
Unsupported or unverifiable hosts fail before the requested target starts.

On Linux, verified runs use a transient user-systemd service and cgroup v2. The guardian holds the
target behind a FIFO start gate, reports the device/inode and effective read-only/read-write mount
state from inside the unit namespace, and releases the target only after the host verifies that
report and the effective systemd properties. Workspace and artifact trees are bounded-scanned
before setup and immediately before release. Sockets, FIFOs, device nodes, cross-filesystem
subtrees, and hard-link aliases outside writable roots are rejected. Creation of sockets,
hard-links, FIFOs/device nodes, mounts, namespaces, and privileged kernel interfaces is denied as
appropriate to the profile.

The verified profiles clear ambient environment variables, use fixed executable search paths,
request private IPC/devices/temporary storage, mask user-systemd, D-Bus, credential, container,
and Nix-daemon control surfaces, apply resource ceilings, and use finite cleanup fuses. Configuration
alone is not accepted: required filesystem masks and mount access are observed from inside the
unit, capability/no-new-privileges/seccomp state is attested there, and effective service
properties are checked before release. Strict-offline commands deny socket creation and SysV/POSIX
message-queue IPC through seccomp even when the host cannot provide a private network or IPC
namespace. Provider-facing profiles exclude AF_UNIX while allowing only the network families
needed to reach the provider.

Some kernels or user-systemd configurations accept namespace-backed properties but silently ignore
individual mounts or private namespaces. MACO detects a visible required mask or incorrect mount
mode at the guardian gate, refuses before target execution, cleans the transient unit and runtime
directory, and reports the backend as unavailable. There is no compatibility downgrade for a run
that requested verified side-effect confinement.

## External Codex

The default Codex executable is resolved only from fixed system locations and must be root-owned,
executable, and not group/world writable. An explicitly supplied absolute executable is limited to
the bounded strict-offline `--version` diagnostic. MACO never starts its requested model target,
never projects `auth.json` or provider credentials into it, grants it no provider network, and
never treats its diagnostic result as publishable.

MACO invokes supported Codex versions with strict, ephemeral configuration, a custom permission
profile, disabled web search/integrations, no inherited shell environment, and model-generated
network access disabled. The outer Codex process may reach its provider; model-generated commands
remain constrained by the inner Codex permission profile and the outer unit boundary.

Strict-backend support is a per-host prerequisite. If the host cannot verify the required user
systemd, cgroup, mount, capability, seccomp, or start-gate evidence, MACO fails closed before the
external target starts and the run cannot become publishable. Destination allowlisting against a
fixed known-hosts set is a later integration boundary and is not claimed by this release. The
current provider profile restricts the process, filesystem, IPC, and permitted address families,
but it does not attest a hostname or IP allowlist.

Only a validated `auth.json` is projected into the unit-lifetime private runtime directory. The
source must be a bounded, no-follow, current-user-owned, single-link regular file with mode 0600
or stricter. MACO does not expose the rest of `CODEX_HOME`. Prompts are bounded and sent on
standard input. An output schema is exposed as one exact read-only file, while result/log
destinations are reserved and bounded separately.

External result files are created before target release as owner-owned `0600`, single-link regular
files under an owner-owned `0700` `incoming` root. MACO retains the read/write descriptor and reads
bounded result bytes from that descriptor after execution; it does not reopen the child-writable
pathname. The parent tee similarly owns the raw-log descriptor, so the log directory is not a
child-writable artifact root. Consult runs use sibling `trusted/` and `incoming/` roots inside the
run container. Supervise runs use sibling `reports/` and `incoming/` roots. Normalized and final
parent reports are reserved before child execution and replaced with descriptor-relative,
no-follow, fsynced atomic writes. Same-UID pathname replacement, symlink, hard-link, and directory
rebind attempts fail closed without following an attacker-selected target.

## Local state and artifact integrity

Patch directories and checkpoint directories must be current-user-owned `0700` directories;
their leaves are `0600` single-link regular files. Patch leaves are reserved for every pending
agent before the schedule starts, are rejected if the output root overlaps any child worktree, and
are removed through identity-checked cleanup when unused. Checkpoint v1 retains one root/file
capability across every stage write, uses bounded descriptor reads for resume, and is protected
against path-confusion and link-following attacks.

Checkpoint v1 is not authenticated state: it has no MAC, signature, monotonic sequence, or external
authority binding. A same-user actor who can write the valid file contents before or after MACO
captures its descriptor can forge a syntactically valid checkpoint. Authenticated checkpoint
v2/WAL authority is a future boundary and is not claimed here. Likewise, the current artifact
`prune` implementation
is intended for quiescent, operator-owned run roots; finalized-only descriptor-relative bounded
deletion and crash scavenging remain part of the pending state-writer integration. Do not prune a
family concurrently with an active run or a hostile same-UID path mutator.

## Resource limits and residual risk

`MemoryMax`, `TasksMax`, CPU quota, descriptor limits, `LimitCORE`, and
`LimitFSIZE` are enforced and checked. `LimitFSIZE` is a per-file ceiling. MACO does **not**
currently provide a total workspace disk quota, so a command can consume free space by creating
many individually bounded files inside an authorized writable root.

Writable workspace and artifact roots are intentional side-effect grants. Linked Git worktrees may
also require an exact Git administrative-directory write grant for MACO's fixed, trusted
`git add -N` index operation. That grant is never given to external/model-generated commands: the
administrative directory and backlink tree are identity/content snapshotted before and after, only
a bounded single-link index replacement is accepted, and a surviving index lock fails the run.
The common object/ref directory remains read-only. Descriptor-held output/state paths explicitly
defend against same-UID pathname substitution, but arbitrary compromise of the same user outside
those capabilities, filesystem or kernel behavior below the verified mount/cgroup boundary, and a
compromised root/systemd/kernel remain outside the complete execution boundary.

Network-provider availability and model correctness are not security evidence. External Claude
consultation is refused because the current integration cannot enforce an equivalent inner
read-only permission contract. Verified side-effect confinement is currently Linux-only.
External Codex uses the fixed `maco_external_codex` inner permission profile in addition to the
outer verified process-tree and side-effect boundary.
Fixed-network confinement is not a caller-constructible general-purpose profile; it is reserved
for the validated external-provider launch path. The Fake supervisor runtime is deterministic
in-process simulation: it does not execute `--codex-bin`, task text, model commands, or network
operations, and it can never produce publishable acceptance. Explicit custom executables used by
verified external runtimes are diagnostic-only as described above and cannot receive credentials,
run the requested model target, or produce publishable acceptance.

## Reporting

Report suspected vulnerabilities privately to the repository owner. Include the MACO version,
host/systemd versions, the requested confinement profile, retained process-tree and side-effect
evidence, and a minimal reproduction. Do not include access tokens, `auth.json`, prompt secrets,
or private repository contents.
