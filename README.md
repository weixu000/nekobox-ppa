# NekoBox Ubuntu packaging

Independent packaging for a Launchpad PPA owned by `~oblivionw26`.
Canonical repository: https://github.com/weixu000/nekobox-ppa
GitHub stores packaging and automation; Launchpad builds signed source uploads
and publishes the PPA.
Supported: Ubuntu 24.04 LTS (noble), 26.04 LTS (resolute), and 26.10
(stonking), amd64.

Source comes from the pinned [upstream release](https://github.com/qr243vbi/nekobox/releases)
recorded in `upstream.env`.

Before publishing: verify a complete offline source build, that the resulting
package owns both GUI and core, and that both executables run.

## Local build

Build the environment with `docker build -t nekobox-ppa-builder:resolute .`,
then run `scripts/prepare-source.sh` and `scripts/build-in-docker.sh`.
The latter disables networking; artifacts and its log stay in ignored `build/`.

Offline builds and isolated installation tests passed for all three targets.
The Launchpad-built packages' cores report v1.13.19; offscreen tests with fresh
profiles confirmed that their launchers start both GUI and packaged core.
Proxy traffic and desktop integration are not yet tested.

Bundled license notices are indexed in `debian/third-party/INDEX.txt`;
remaining provenance uncertainties are recorded in `debian/copyright`.
PPA: https://launchpad.net/~oblivionw26/+archive/ubuntu/nekobox
Packages are published for all three targets.
Source uploads use a series-specific version suffix (for example,
`~ubuntu26.04.1`); bump the packaging revision for subsequent packaging uploads.

## Upstream updates

GitHub Actions checks stable releases daily, downloads the pinned source and
validates all supported Ubuntu targets. It uploads signed source packages;
Launchpad compiles the official binaries. Publication is checked every six hours.
No desktop scheduler is required. See
[UPDATE-WORKFLOW.md](UPDATE-WORKFLOW.md) for validation and publication.
Run `scripts/check-upstream.py` for a read-only check at any time.
