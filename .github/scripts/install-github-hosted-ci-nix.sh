#!/usr/bin/env bash
# Only the GitHub-hosted ephemeral Linux runner may run this installer.
set -euo pipefail
test "$RUNNER_ENVIRONMENT" = github-hosted
test "$RUNNER_OS" = Linux
test "$RUNNER_ARCH" = X64
test ! -e /nix
test ! -e /etc/nix
umask 077
lane="$(mktemp -d "$RUNNER_TEMP/nix-package.XXXXXXXX")"
archive="$lane/nix-2.35.2-x86_64-linux.tar.xz"
# SHA256 published in https://releases.nixos.org/nix/nix-2.35.2/install.
env -i PATH=/usr/bin:/bin /usr/bin/curl --disable \
  --fail --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 15 --max-time 300 --retry 0 \
  --output "$archive" \
  https://releases.nixos.org/nix/nix-2.35.2/nix-2.35.2-x86_64-linux.tar.xz
printf '%s  %s\n' \
  0c3960a9792331a22081c3c7a5d8465db9b17c50b3acdf18587fa4c6f2cb1158 \
  "$archive" | sha256sum --check --strict
# Preserve public store readability inside the private transport lane.
(umask 022; tar --extract --xz --file "$archive" --directory "$lane" --no-same-owner)
mkdir -m 0700 "$lane/home"
cat > "$lane/nix.conf" <<'CONF'
experimental-features = nix-command flakes
sandbox = true
max-jobs = 1
cores = 1
allow-import-from-derivation = false
CONF
# Only the verified official installer runs with ephemeral runner root.
# The daemon installer still edits system profiles in this Nix version.
sudo -n /usr/bin/env -i \
  HOME=/root USER=root LOGNAME=root \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  TMPDIR="$lane" NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
  /bin/sh "$lane/nix-2.35.2-x86_64-linux/install" \
  --daemon --yes --no-modify-profile --no-channel-add \
  --daemon-user-count 1 --nix-extra-conf-file "$lane/nix.conf" < /dev/null
printf 'lane=%s\n' "$lane" >> "$GITHUB_OUTPUT"
