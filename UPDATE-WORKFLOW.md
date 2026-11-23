# Stable upstream updates

GitHub stores packaging, patches and automation. Upstream release archives are
downloaded into ignored working directories.
Launchpad receives signed Debian source packages, compiles the official binaries
and publishes the existing [PPA](https://launchpad.net/~oblivionw26/+archive/ubuntu/nekobox).

## Release procedure

GitHub Actions owns daily release discovery and validation; no desktop scheduler
is needed. See `.github/workflows/upstream-update.yml` for triggers and manual
modes (`validate`, `auto`, `reconcile`). Manual publication requires `publish=true`.
`.github/workflows/verify-published.yml` checks publication every six hours.

1. Detect a newer stable release with `scripts/check-upstream.py`. Ignore drafts
   and prereleases; never downgrade. A failed check is not an up-to-date result.
2. Pin its URL, version and checksum in `upstream.env`, update the changelog and
   regenerate bundled notices. Review dependency and licence changes.
3. Download and verify the archive, overlay `debian/`, and build offline for
   every supported target. Verify both GUI and matching core and run the isolated
   launcher smoke test.
4. Assemble a `3.0 (quilt)` source upload for each target. Check its contents,
   re-extract it, and sign its source metadata and upload manifest.
5. Only after validation passes, publish the packaging update to GitHub and
   upload missing source versions to Launchpad. Never upload the test `.deb`
   binaries: Launchpad builds those itself.
6. Verify Launchpad build status, source checksums and published binaries.
   Do not install on the host or change its apt sources.

## Versions and retries

Each Ubuntu series gets a distinct version suffix. Already submitted versions
are not overwritten; increment the packaging revision for a changed package.
Launchpad rejects different bytes under an existing source filename. Our uploader
reuses the archive's orig tarball for an existing upstream version, including its
compression format, so packaging revisions do not introduce alternate origs.

Publication is asynchronous. Missing packages may be pending; failed builds and
states older than 24 hours need investigation. Use the manual `reconcile`
mode in the update workflow to retry missing submissions without inventing a
new upstream release.

## Signing and activation

Standard source uploads require an OpenPGP signing key registered to the
Launchpad uploader, separate from Launchpad's PPA repository-signing key.
Use a key with an encryption subkey: Launchpad sends encrypted
confirmation mail. Publish the public key to `keyserver.ubuntu.com` and complete
[key registration](https://launchpad.net/~/+editpgpkeys).

Configure GitHub Actions secrets:
- `LP_GPG_PRIVATE_KEY`: armored private upload key.
- `LP_GPG_PASSPHRASE`: passphrase, if the key is protected.
- `LP_GPG_KEY_ID`: optional full primary fingerprint guard.

The workflow imports the key into a temporary keyring, checks its Launchpad
registration before publication, and removes the keyring afterwards. Never put
credentials in Git, artifacts or logs. Start with manual `validate`; then use
`reconcile` with publication enabled. Already published versions are skipped, so
an actual upload is verified on the next new package version.

Uploads go to the existing PPA address, so users' apt configuration does not
change.

GitHub can disable scheduled workflows after 60 days without repository activity.
Re-enable the workflow in the Actions tab if needed; scheduled runs may be delayed.
