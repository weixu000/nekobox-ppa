#!/bin/bash
# Binary build inside the pinned builder image, fully offline.
#
# Usage: scripts/build-in-docker.sh [extra dpkg-buildpackage arguments]
#
# Properties, on purpose:
#   * only the project's build/ directory is mounted (at /build); the repo,
#     the host home and reference/ are not visible to the container
#   * the container runs with the caller's UID/GID, HOME=/tmp is writable
#   * --network=none: the build must not reach the network
#   * full output is captured in build/offline-build.log
#
# Requires build/nekobox-<version>/ from scripts/prepare-source.sh.
set -euo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck disable=SC1091 # upstream.env is a sibling data file, not a library
# shellcheck source=../upstream.env
. "$repo_root/upstream.env"

image=${IMAGE:-nekobox-ppa-builder:resolute}
tree=nekobox-$UPSTREAM_VERSION
log=$repo_root/build/offline-build.log
jobs=${JOBS:-6}

command -v docker >/dev/null 2>&1 || die "docker not found"
[ -f "$repo_root/build/$tree/debian/control" ] \
    || die "build/$tree is missing; run scripts/prepare-source.sh first"

image_id=$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null) \
    || die "image $image not found"

{
    printf '# image: %s (%s)\n' "$image" "$image_id"
    printf '# date: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '# uid:gid: %s:%s\n' "$(id -u)" "$(id -g)"
    printf '# network: none\n'
    printf '# mount: %s:/build\n' "$repo_root/build"
    printf '# HOME=/tmp\n'
    printf '# DEB_BUILD_OPTIONS=parallel=%s GOMAXPROCS=%s\n' "$jobs" "$jobs"
} >"$log"

note "building $tree in $image (log: $log)"
set +e
docker run --rm \
    --network=none \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --env LC_ALL=C.UTF-8 \
    --env DPKG_COLORS=never \
    --env DEB_BUILD_OPTIONS="parallel=$jobs" \
    --env GOMAXPROCS="$jobs" \
    --volume "$repo_root/build:/build" \
    --workdir "/build/$tree" \
    "$image" \
    dpkg-buildpackage -b -us -uc "$@" 2>&1 | tee -a "$log"
rc=${PIPESTATUS[0]}
set -e

printf '# exit: %s\n' "$rc" >>"$log"
if [ "$rc" -ne 0 ]; then
    printf 'error: build failed with exit %s; first error below\n' "$rc" >&2
    grep -n -m1 -E '(^|: )(error|Error|ERROR|fatal error)' "$log" >&2 || true
    exit "$rc"
fi
note "build succeeded"
ls -l "$repo_root/build"/*.deb "$repo_root/build"/*.changes 2>/dev/null || true
