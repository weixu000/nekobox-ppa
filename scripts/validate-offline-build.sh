#!/bin/bash
# Validate the prepared source on one Ubuntu series inside Docker.
#
# Usage: scripts/validate-offline-build.sh --series noble --base ubuntu:24.04
#        [--tree PATH --version VERSION]
#
# The container installs the series' debian/control Build-Depends (resolved
# from that series' archive, including -security), is committed, and then the
# existing scripts/build-in-docker.sh builds with --network=none.  Finally the
# .deb is installed in the same image and scripts/smoke-test-package.sh checks
# the GUI, the core, and the bundled notices.
#
# Requires build/nekobox-<version>/ from scripts/prepare-source.sh.
set -euo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }

series=
base=
source_tree=
package_version=
while [ $# -gt 0 ]; do
    case "$1" in
        --series) shift; series=${1:-} ;;
        --base) shift; base=${1:-} ;;
        --tree) shift; source_tree=${1:-} ;;
        --version) shift; package_version=${1:-} ;;
        -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done
[ -n "$series" ] || die "--series is required"
[ -n "$base" ] || die "--base is required (for example ubuntu:24.04)"
command -v docker >/dev/null 2>&1 || die "docker not found"

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck disable=SC1091 # upstream.env is a sibling data file, not a library
# shellcheck source=../upstream.env
. "$repo_root/upstream.env"

source_tree=$(realpath "${source_tree:-$repo_root/build/nekobox-$UPSTREAM_VERSION}")
case "$source_tree" in
    "$repo_root/build/"*) tree=${source_tree#"$repo_root/build/"} ;;
    *) die "--tree must be inside $repo_root/build/" ;;
esac
base_version=${package_version:-$UPSTREAM_VERSION-$DEBIAN_REVISION}
image=${IMAGE:-nekobox-ppa-validate:$series}
container=nekobox-ppa-validate-$series-$$
[ -d "$repo_root/build/$tree/debian" ] \
    || die "build/$tree is missing; run scripts/prepare-source.sh first"

cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

note "starting $base for $series"
docker run --detach --name "$container" \
    --volume "$repo_root/build:/build" \
    --workdir "/build/$tree" \
    --env DEBIAN_FRONTEND=noninteractive \
    "$base" sleep infinity >/dev/null

note "installing $series Build-Depends from the series archive"
docker exec -i "$container" bash -s <<'EOF'
set -euo pipefail
. /etc/os-release
echo "series: $PRETTY_NAME"
if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
    sed -i -E 's/^Types:[[:space:]]*deb[[:space:]]*$/Types: deb deb-src/' \
        /etc/apt/sources.list.d/ubuntu.sources
    if ! grep -q 'deb-src' /etc/apt/sources.list.d/ubuntu.sources; then
        echo "error: could not enable deb-src in ubuntu.sources" >&2
        exit 1
    fi
else
    printf 'deb-src http://archive.ubuntu.com/ubuntu %s main universe\n' \
        "$VERSION_CODENAME" >/etc/apt/sources.list.d/nekobox-src.list
    printf 'deb-src http://security.ubuntu.com/ubuntu %s-security main universe\n' \
        "$VERSION_CODENAME" >>/etc/apt/sources.list.d/nekobox-src.list
fi
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    build-essential ca-certificates devscripts dpkg-dev fakeroot xz-utils
apt-get build-dep -y -qq .
apt-get clean
rm -rf /var/lib/apt/lists/*
EOF

docker commit "$container" "$image" >/dev/null
cleanup
trap - EXIT
docker run --rm "$image" bash -c 'command -v dpkg-buildpackage >/dev/null' \
    || die "validation image $image lost its dpkg-dev installation"
note "built validation image $image"

note "building the package offline"
IMAGE="$image" JOBS="${JOBS:-$(nproc)}" BUILD_TREE="$source_tree" \
    "$repo_root/scripts/build-in-docker.sh"

deb=$(find "$(dirname "$source_tree")" -maxdepth 1 -type f \
    -name "nekobox_${base_version}_*.deb" -print -quit)
[ -n "$deb" ] || die "no nekobox .deb for $base_version was produced"

note "smoke-testing $deb in $image"
docker run --rm --network=none \
    --volume "$repo_root/build:/build:ro" \
    --volume "$repo_root/scripts:/scripts:ro" \
    --volume "$repo_root/debian/third-party/INDEX.txt:/expected/INDEX.txt:ro" \
    "$image" bash /scripts/smoke-test-package.sh \
        --deb "/build/${deb#"$repo_root/build/"}" \
        --version "$base_version" \
        --expected-index /expected/INDEX.txt \
        --series "$series"

printf '\nvalidated %s on %s: %s\n' "$base_version" "$series" "$deb"
