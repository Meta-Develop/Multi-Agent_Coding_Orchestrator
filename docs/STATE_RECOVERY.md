# State recovery

## Offline recovery for an unanchored claims journal

Use this procedure only for the exact failure where the reviewed current
development binary reports an authenticated claims physical journal that is not
anchored by any signed logical state, while the legacy `claims.json` is the
checksum-less version-1 state independently reviewed by the operator. Do not
use it for a different inventory, authentication, rollback, or incomplete
initialization error.

The repository must remain offline for the entire procedure: stop every MACO
writer and verify that none can restart. Do not delete, replace, or "repair"
`claims.lock`; a lock error is a reason to abort. Run the commands below from
one Bash session, replace the two absolute placeholders, and stop on every
unexpected result:

```bash
set -euo pipefail
umask 077
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE
unset GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

REPO=/absolute/path/to/repository
REPO=$(realpath -e -- "$REPO")
DEV=/absolute/path/to/reviewed-current-dev-maco
PINNED_PATH="$REPO/.agents/scripts/maco"
test -x "$PINNED_PATH"
test -f "$PINNED_PATH"
test ! -L "$PINNED_PATH"
PINNED=$(realpath -e -- "$PINNED_PATH")
COMMON=$(git -C "$REPO" rev-parse --path-format=absolute --git-common-dir)
COMMON=$(realpath -e -- "$COMMON")
STATE="$COMMON/maco/state"
ORPHAN="$STATE/authenticated-claims-state-v1"
RECOVERY_BASE="$COMMON/maco/offline-recovery"

test -x "$DEV"
mv --version | grep -F 'GNU coreutils' >/dev/null
mv --no-copy --help >/dev/null
test -d "$STATE"
test -d "$ORPHAN"
test ! -L "$ORPHAN"
test -f "$STATE/claims.json"
test ! -L "$STATE/claims.json"
test ! -L "$RECOVERY_BASE"

install -d -m 0700 -- "$RECOVERY_BASE"
test ! -L "$RECOVERY_BASE"
RECOVERY=$(mktemp -d "$RECOVERY_BASE/issue33.XXXXXXXX")
chmod 0700 -- "$RECOVERY"
test "$(stat -c %a -- "$RECOVERY")" = 700
```

First prove the current failure. Both fixed fragments must occur in stderr; a
successful command or any other error is outside this procedure:

```bash
set +e
"$DEV" sync status --repo "$REPO" --json \
  >"$RECOVERY/dev-before.stdout" \
  2>"$RECOVERY/dev-before.stderr"
DEV_STATUS=$?
set -e

test "$DEV_STATUS" -ne 0
grep -Fq "authenticated snapshot physical journal '" \
  "$RECOVERY/dev-before.stderr"
grep -Fq "is not anchored by any signed logical state" \
  "$RECOVERY/dev-before.stderr"
```

The development command acquires the live persistent kernel lock before
reporting the inventory error. Bind that lock's identity and copy the exact
plaintext claims bytes before invoking the pin:

```bash
test -f "$STATE/claims.lock"
test ! -L "$STATE/claims.lock"
LIVE_CLAIMS_LOCK_ID=$(stat -c '%d:%i:%s:%f:%h' -- "$STATE/claims.lock")

cp -- "$STATE/claims.json" "$RECOVERY/claims-v1.reviewed.json"
chmod 0600 -- "$RECOVERY/claims-v1.reviewed.json"
cmp -s -- "$STATE/claims.json" "$RECOVERY/claims-v1.reviewed.json"
```

The registry pin must never run against the live repository: its legacy
create-new PID lock is incompatible with the live persistent kernel lock and
could otherwise fail on or remove a stale parseable `claims.lock`. Instead,
create an isolated throwaway Git repository under the owner-private recovery
directory, prove that it has a different Git common directory, and give it only
the copied plaintext claims-v1. For this incident, the exact reviewed wrapper
has SHA-256
`93b76ebff318fb75e44f8ce48b5b48b4bad5435045d9fe736c4e1fc587a0d814`.
Its own project-root resolution must bind it to `REPO`, and its manifest path
must resolve inside the reviewed attached checkout. That checkout must be
commit `373550870f9986224bc8b57a9b13019a3da02516` with a clean index and
worktree, including no untracked files. The commit reads and writes plaintext
claims-v1 and contains no authenticated-claims journal writer. Its isolated
output therefore proves only which copied plaintext claim view it interpreted;
it does not prove that the captured orphan journal was emitted by that pin.

```bash
PINNED_WRAPPER_SHA256=93b76ebff318fb75e44f8ce48b5b48b4bad5435045d9fe736c4e1fc587a0d814
test "$(sha256sum -- "$PINNED" | cut -d ' ' -f 1)" \
  = "$PINNED_WRAPPER_SHA256"
PINNED_WRAPPER_ID=$(stat -c '%d:%i:%s:%f:%h' -- "$PINNED")
PINNED_PROJECT_ROOT=$(cd -- "$(dirname -- "$PINNED")/../.." && pwd -P)
test "$PINNED_PROJECT_ROOT" = "$REPO"

PINNED_CHECKOUT=$(realpath -e -- \
  "$PINNED_PROJECT_ROOT/.agents/external/multi-agent-coding-orchestrator")
test "$(realpath -e -- \
  "$PINNED_PROJECT_ROOT/.agents/external/multi-agent-coding-orchestrator/Cargo.toml")" \
  = "$PINNED_CHECKOUT/Cargo.toml"
test "$(realpath -e -- "$(git -C "$PINNED_CHECKOUT" rev-parse --show-toplevel)")" \
  = "$PINNED_CHECKOUT"
PINNED_HEAD=$(git -C "$PINNED_CHECKOUT" rev-parse --verify 'HEAD^{commit}')
printf '%s\n' "$PINNED_HEAD" >"$RECOVERY/pinned-head.txt"
test "$PINNED_HEAD" = 373550870f9986224bc8b57a9b13019a3da02516
git -C "$PINNED_CHECKOUT" status --porcelain=v1 \
  --untracked-files=all --ignore-submodules=none \
  >"$RECOVERY/pinned-checkout-status.before"
test ! -s "$RECOVERY/pinned-checkout-status.before"

PINNED_STAGE="$RECOVERY/pinned-plaintext-stage"
test ! -e "$PINNED_STAGE"
git init --quiet -- "$PINNED_STAGE"
PINNED_STAGE_COMMON=$(git -C "$PINNED_STAGE" \
  rev-parse --path-format=absolute --git-common-dir)
PINNED_STAGE_COMMON=$(realpath -e -- "$PINNED_STAGE_COMMON")
test "$PINNED_STAGE_COMMON" != "$COMMON"
test "$(stat -c %d -- "$PINNED_STAGE_COMMON")" \
  = "$(stat -c %d -- "$RECOVERY")"

PINNED_STATE="$PINNED_STAGE_COMMON/maco/state"
test ! -L "$PINNED_STATE"
install -d -m 0700 -- "$PINNED_STATE"
test ! -L "$PINNED_STATE"
cp -- "$RECOVERY/claims-v1.reviewed.json" "$PINNED_STATE/claims.json"
chmod 0600 -- "$PINNED_STATE/claims.json"
cmp -s -- \
  "$RECOVERY/claims-v1.reviewed.json" \
  "$PINNED_STATE/claims.json"

CARGO_NET_OFFLINE=true \
CARGO_INCREMENTAL=0 \
CARGO_TARGET_DIR="$RECOVERY/pinned-cargo-target" \
  "$PINNED" sync status --repo "$PINNED_STAGE" --json \
  >"$RECOVERY/pinned-claims-view.json" \
  2>"$RECOVERY/pinned-claims-view.stderr"
test ! -e "$PINNED_STATE/claims.lock"
test "$(stat -c '%d:%i:%s:%f:%h' -- "$PINNED")" = "$PINNED_WRAPPER_ID"
test "$(sha256sum -- "$PINNED" | cut -d ' ' -f 1)" \
  = "$PINNED_WRAPPER_SHA256"
test "$(git -C "$PINNED_CHECKOUT" rev-parse --verify 'HEAD^{commit}')" \
  = "$PINNED_HEAD"
git -C "$PINNED_CHECKOUT" status --porcelain=v1 \
  --untracked-files=all --ignore-submodules=none \
  >"$RECOVERY/pinned-checkout-status.after"
test ! -s "$RECOVERY/pinned-checkout-status.after"
cmp -s -- \
  "$RECOVERY/pinned-checkout-status.before" \
  "$RECOVERY/pinned-checkout-status.after"
cmp -s -- "$STATE/claims.json" "$RECOVERY/claims-v1.reviewed.json"
test "$(stat -c '%d:%i:%s:%f:%h' -- "$STATE/claims.lock")" \
  = "$LIVE_CLAIMS_LOCK_ID"

jq -e 'type == "object" and .version == 1
  and (.next_token | type == "number")
  and (.claims | type == "array")' \
  "$RECOVERY/claims-v1.reviewed.json" >/dev/null
jq -e 'type == "array"' "$RECOVERY/pinned-claims-view.json" >/dev/null
jq -S '.claims' "$RECOVERY/claims-v1.reviewed.json" \
  >"$RECOVERY/raw-claims.sorted.json"
jq -S '.' "$RECOVERY/pinned-claims-view.json" \
  >"$RECOVERY/pinned-claims.sorted.json"
cmp -s -- \
  "$RECOVERY/raw-claims.sorted.json" \
  "$RECOVERY/pinned-claims.sorted.json"
jq '.next_token' "$RECOVERY/claims-v1.reviewed.json"
```

The last command only displays `next_token`: it is not present in the pinned
status array and must be reviewed separately with the entire copied claims-v1
file.

Inventory and hash every entry in the orphan namespace before changing its
active path. The inventory includes type, mode, ownership, size, device, inode,
link count, path, and symlink target; the hash list covers every regular file.
The `-P` and `-xdev` boundaries prevent following links or crossing a mounted
filesystem. Abort if any visited entry is nevertheless on another device.

```bash
inventory_tree() {
  (
    cd -- "$1"
    find -P . -xdev \
      -printf '%y\t%m\t%U\t%G\t%s\t%D\t%i\t%n\t%P\t%l\0' |
      LC_ALL=C sort -z
  )
}

hash_tree() {
  (
    cd -- "$1"
    find -P . -xdev -type f -print0 |
      LC_ALL=C sort -z |
      xargs -0r sha256sum -z --
  )
}

ORPHAN_DEVICE=$(stat -c %d -- "$ORPHAN")
while IFS= read -r -d '' ENTRY; do
  test "$(stat -c %d -- "$ENTRY")" = "$ORPHAN_DEVICE"
done < <(find -P "$ORPHAN" -xdev -print0)

inventory_tree "$ORPHAN" >"$RECOVERY/orphan.inventory.before"
hash_tree "$ORPHAN" >"$RECOVERY/orphan.sha256.before"
sync -f -- "$RECOVERY"
```

The prerequisite checks above require GNU Coreutils `mv` with `--no-copy`.
Prove the orphan namespace and recovery directory are on the same filesystem,
then atomically quarantine the complete namespace with one rename. `--no-copy`
makes a failed rename fail closed instead of falling back to copy-and-delete.
Do not copy individual journals or synthesize a locator. The quarantined
namespace is forensic evidence and must never be adopted, re-anchored, restored
into active state, or used as migration input.

```bash
test "$(stat -c %d -- "$ORPHAN")" = "$(stat -c %d -- "$RECOVERY")"
test "$(stat -c %d -- "$STATE")" = "$(stat -c %d -- "$RECOVERY")"
QUARANTINED="$RECOVERY/authenticated-claims-state-v1"
test ! -e "$QUARANTINED"

mv --no-copy -T -- "$ORPHAN" "$QUARANTINED"
test ! -e "$ORPHAN"
sync -f -- "$STATE" "$RECOVERY"

inventory_tree "$QUARANTINED" >"$RECOVERY/orphan.inventory.after"
hash_tree "$QUARANTINED" >"$RECOVERY/orphan.sha256.after"
cmp -s -- \
  "$RECOVERY/orphan.inventory.before" \
  "$RECOVERY/orphan.inventory.after"
cmp -s -- \
  "$RECOVERY/orphan.sha256.before" \
  "$RECOVERY/orphan.sha256.after"
sync -f -- "$RECOVERY"
```

If any command after the rename fails, keep all writers offline and leave the
quarantine in place for investigation; do not automatically move it back.

Manually inspect the complete `claims-v1.reviewed.json`, including
`next_token`, agent ids, tokens, and every path. Compute the digest independently
of MACO, paste the reviewed lowercase value, and verify it against both the
review copy and the still-active plaintext file:

```bash
sha256sum -- "$RECOVERY/claims-v1.reviewed.json"
read -r -p "Paste the reviewed lowercase SHA-256: " EXPECTED
test "${#EXPECTED}" -eq 64
case "$EXPECTED" in
  *[!0-9a-f]*) exit 1 ;;
esac
test "$(sha256sum -- "$RECOVERY/claims-v1.reviewed.json" | cut -d ' ' -f 1)" \
  = "$EXPECTED"
test "$(sha256sum -- "$STATE/claims.json" | cut -d ' ' -f 1)" \
  = "$EXPECTED"
cmp -s -- "$STATE/claims.json" "$RECOVERY/claims-v1.reviewed.json"
```

Run the attested migration with the reviewed development binary. Dry-run must
report `ready` or `already_applied`; apply must report `applied` or
`already_applied`:

```bash
"$DEV" state migrate --repo "$REPO" \
  --acknowledge-unauthenticated-claims-v1 \
  --expected-claims-v1-sha256 "$EXPECTED" \
  --json >"$RECOVERY/migration-dry-run.json"
jq -e '.mode == "dry_run"
  and (.status == "ready" or .status == "already_applied")' \
  "$RECOVERY/migration-dry-run.json" >/dev/null

"$DEV" state migrate --repo "$REPO" --apply \
  --acknowledge-unauthenticated-claims-v1 \
  --expected-claims-v1-sha256 "$EXPECTED" \
  --json >"$RECOVERY/migration-apply.json"
jq -e '.mode == "apply"
  and (.status == "applied" or .status == "already_applied")' \
  "$RECOVERY/migration-apply.json" >/dev/null
```

Finally, let the development binary create/open the new authenticated claims
snapshot from the signed claims-v1 migration, compare its claims to the pinned
plaintext view, and inspect worktree cleanup without removing anything. A
legitimate dry-run can report eligible worktrees, targets, or orphan directories,
so require only `dry_run == true` and review every reported entry rather than
requiring zero counts.

```bash
"$DEV" sync status --repo "$REPO" --json \
  >"$RECOVERY/dev-claims-after.json"
jq -e 'type == "array"' "$RECOVERY/dev-claims-after.json" >/dev/null
jq -S '.' "$RECOVERY/dev-claims-after.json" \
  >"$RECOVERY/dev-claims-after.sorted.json"
cmp -s -- \
  "$RECOVERY/pinned-claims.sorted.json" \
  "$RECOVERY/dev-claims-after.sorted.json"

"$DEV" worktree gc --repo "$REPO" --dry-run --json \
  >"$RECOVERY/worktree-gc-dry-run.json"
jq -e '.dry_run == true' "$RECOVERY/worktree-gc-dry-run.json" >/dev/null

inventory_tree "$QUARANTINED" >"$RECOVERY/orphan.inventory.final"
hash_tree "$QUARANTINED" >"$RECOVERY/orphan.sha256.final"
cmp -s -- \
  "$RECOVERY/orphan.inventory.before" \
  "$RECOVERY/orphan.inventory.final"
cmp -s -- \
  "$RECOVERY/orphan.sha256.before" \
  "$RECOVERY/orphan.sha256.final"
sync -f -- "$STATE" "$RECOVERY"
```

Review the migration, sync-status, and GC reports and keep the full quarantine
before resuming writers. Never run the registry-pinned writer against the live
repository at any point; its only permitted invocation is against the isolated
pre-migration staging repository above. After migration, resume only the
reviewed development binary. The new authenticated claims snapshot is
supported by the attested claims-v1 migration; the captured orphan journal
remains unanchored and unadopted. Neither its writer provenance nor its
authorization as the current logical state was established. The wrapper checks
bind the reviewed script bytes, its project root, its resolved manifest, and the
clean pinned source checkout before and after the isolated invocation. They do
not independently attest Cargo, rustc, cached dependencies, or the wider
toolchain, and they do not defend against a hostile same-UID process racing and
restoring checked paths during execution; the exclusive offline operator
boundary remains a prerequisite.
