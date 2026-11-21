# NekoBox Ubuntu packaging

Independent packaging for a Launchpad PPA owned by `~oblivionw26`.
Initial target: Ubuntu 26.04 (resolute), amd64.

Source comes from the pinned [upstream release](https://github.com/qr243vbi/nekobox/releases)
recorded in `upstream.env`, not the existing PPA's Git history.

Before publishing: verify a complete offline source build, that the resulting
package owns both GUI and core, and that both executables run.

## Local build

Build the environment with `docker build -t nekobox-ppa-builder:resolute .`,
then run `scripts/prepare-source.sh` and `scripts/build-in-docker.sh`.
The latter disables networking; artifacts and its log stay in ignored `build/`.

Version `5.11.28.3-2~ppa1` built successfully on resolute amd64. Its core
reports v1.13.19; the GUI survived a 12-second offscreen smoke test using a
fresh profile. Installing the `.deb` in the isolated container also confirmed
that the packaged launcher starts both GUI and core, with their Unix sockets
present. Proxy traffic and desktop integration are not yet tested.

Bundled license notices are indexed in `debian/third-party/INDEX.txt`;
remaining provenance uncertainties are recorded in `debian/copyright`.
PPA: https://launchpad.net/~oblivionw26/+archive/ubuntu/nekobox
Recipe: https://code.launchpad.net/~oblivionw26/+recipe/nekobox
The first Launchpad build has been requested; publication is not yet verified.
Daily builds are disabled. Launchpad appends `~ubuntu26.04.1` to the recipe's
base version; bump the base for subsequent packaging uploads.

## Upstream updates

Stable releases are checked daily by OpenChamber. See
[UPDATE-WORKFLOW.md](UPDATE-WORKFLOW.md) for validation and publication.
Run `scripts/check-upstream.py` for a read-only check at any time.
