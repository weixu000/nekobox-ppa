#!/bin/bash
# Non-interactive gpg signer for dpkg-buildpackage.
#
# dpkg-buildpackage --sign-backend=gpg invokes the --sign-command with the
# normal gpg arguments.  The CI keyring lives in a disposable GNUPGHOME under
# RUNNER_TEMP; the passphrase, when present, is read from a mode-600 file and
# is never passed on the command line or printed.
set -euo pipefail

args=(--batch --no-tty --pinentry-mode loopback)
if [ -n "${LP_GPG_PASSPHRASE_FILE:-}" ]; then
    [ -f "$LP_GPG_PASSPHRASE_FILE" ] \
        || { echo "error: LP_GPG_PASSPHRASE_FILE does not exist" >&2; exit 1; }
    args+=(--passphrase-file "$LP_GPG_PASSPHRASE_FILE")
else
    args+=(--passphrase '')
fi

exec gpg "${args[@]}" "$@"
