#!/bin/bash
# Prepare the ignored build/ tree for this source package.
#
# Usage: scripts/prepare-source.sh [--refresh-download] [--repack]
#
#   --refresh-download  ignore the copy in downloads/ and fetch again
#   --repack            always repack the orig tarball under nekobox-<version>/
#                       instead of reusing the upstream tarball bytes
#
# Steps:
#   1. download the pinned upstream release into downloads/ (cached) and
#      verify UPSTREAM_SHA256 from upstream.env;
#   2. unpack it under build/nekobox-<version>/ and overlay ./debian/;
#   3. create build/nekobox_<version>.orig.tar.xz: the upstream bytes are
#      reused unchanged when dpkg-source accepts them, otherwise the same file
#      contents are repacked under the Debian top-level directory name;
#   4. run dpkg-source -b, then re-extract the generated source package to
#      prove it is complete (debian/ and upstream sources both present).
#
# Only the pinned release is used as source. reference/ is a comparison clone
# and is never read by this script. No binary package is built here.
set -euo pipefail

umask 022

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck disable=SC1091 # upstream.env is a sibling data file, not a library
# shellcheck source=../upstream.env
. "$repo_root/upstream.env"

for var in UPSTREAM_VERSION UPSTREAM_TARBALL UPSTREAM_URL UPSTREAM_SHA256 \
           UPSTREAM_TOP_DIR UPSTREAM_SOURCE_DATE_EPOCH; do
    [ -n "${!var:-}" ] || die "upstream.env does not define $var"
done

refresh=0
force_repack=0
while [ $# -gt 0 ]; do
    case "$1" in
        --refresh-download) refresh=1 ;;
        --repack) force_repack=1 ;;
        -h|--help) sed -n '2,21p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

for tool in curl sha256sum tar xz dpkg-source; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done

cache_dir=$repo_root/downloads
build_dir=$repo_root/build
tarball=$cache_dir/$UPSTREAM_TARBALL
tree=$build_dir/nekobox-$UPSTREAM_VERSION
orig=$build_dir/nekobox_$UPSTREAM_VERSION.orig.tar.xz
stage=$build_dir/.stage-$UPSTREAM_VERSION
roundtrip=$build_dir/.roundtrip
source_log=$build_dir/dpkg-source.log

cleanup() { rm -rf "$stage" "$roundtrip"; }
trap cleanup EXIT

mkdir -p "$cache_dir" "$build_dir"

# ---------------------------------------------------------------- download ---
if [ "$refresh" -eq 1 ]; then
    rm -f "$tarball"
fi
if [ ! -f "$tarball" ]; then
    note "downloading $UPSTREAM_URL"
    tmp=$tarball.part
    curl --fail --location --retry 3 --retry-delay 2 --output "$tmp" \
        "$UPSTREAM_URL" \
        || die "download failed (set http_proxy/https_proxy when the network needs a proxy)"
    mv -f "$tmp" "$tarball"
else
    note "using cached $tarball"
fi

note "verifying sha256"
actual=$(sha256sum "$tarball" | awk '{print $1}')
[ "$actual" = "$UPSTREAM_SHA256" ] \
    || die "sha256 mismatch for $tarball: expected $UPSTREAM_SHA256, got $actual"

# ----------------------------------------------------------------- unpack ---
note "unpacking upstream release"
rm -rf "$stage" "$tree"
mkdir -p "$stage"
tar -xJf "$tarball" -C "$stage"
[ -d "$stage/$UPSTREAM_TOP_DIR" ] \
    || die "tarball has no top-level directory $UPSTREAM_TOP_DIR"
if [ -e "$stage/$UPSTREAM_TOP_DIR/debian" ]; then
    note "discarding upstream debian/ (packaging comes from this repository)"
    rm -rf "$stage/$UPSTREAM_TOP_DIR/debian"
fi
mv "$stage/$UPSTREAM_TOP_DIR" "$stage/nekobox-$UPSTREAM_VERSION"

note "installing source tree $tree"
cp -a "$stage/nekobox-$UPSTREAM_VERSION" "$tree"
rm -rf "$tree/debian"
cp -a "$repo_root/debian" "$tree/debian"
chmod 0755 "$tree/debian/rules"

# ------------------------------------------------------------------- orig ---
build_source() {
    ( cd "$tree" && dpkg-source -b . ) >"$source_log" 2>&1
}

drop_source_artifacts() {
    rm -f "$build_dir"/*.dsc "$build_dir"/*.debian.tar.* "$orig"
}

repack_orig() {
    note "repacking $UPSTREAM_TARBALL as nekobox-$UPSTREAM_VERSION (contents unchanged)"
    rm -f "$orig.tmp"
    ( cd "$stage" && tar --sort=name \
            --mtime="@$UPSTREAM_SOURCE_DATE_EPOCH" \
            --owner=0 --group=0 --numeric-owner --format=gnu \
            -cf - "nekobox-$UPSTREAM_VERSION" ) \
        | xz -6 -T1 -c >"$orig.tmp"
    mv -f "$orig.tmp" "$orig"
}

reused=0
drop_source_artifacts
if [ "$force_repack" -eq 0 ]; then
    note "trying the upstream tarball bytes unchanged as $orig"
    cp -f "$tarball" "$orig"
    if build_source; then
        reused=1
        note "dpkg-source accepted the upstream tarball unchanged"
    else
        note "dpkg-source rejected the upstream tarball: $(tail -n 1 "$source_log")"
    fi
fi
if [ "$reused" -eq 0 ]; then
    drop_source_artifacts
    repack_orig
    build_source || die "dpkg-source -b failed after repacking; see $source_log"
    first=$( { tar -tJf "$orig" || true; } | awk 'NR == 1 { print; exit }')
    case "$first" in
        "nekobox-$UPSTREAM_VERSION/"*)
            note "dpkg-source accepted the repacked orig tarball" ;;
        *) die "repacked orig tarball has an unexpected top-level path: $first" ;;
    esac
fi

# ------------------------------------------------------------- validation ---
dsc=
dtar=
for f in "$build_dir/nekobox_$UPSTREAM_VERSION"*.dsc; do
    if [ -e "$f" ]; then dsc=$f; break; fi
done
for f in "$build_dir/nekobox_$UPSTREAM_VERSION"*.debian.tar.xz; do
    if [ -e "$f" ]; then dtar=$f; break; fi
done
[ -n "$dsc" ] && [ -n "$dtar" ] || die "dpkg-source did not produce a .dsc/.debian.tar.xz pair"

# The debian tarball must only carry packaging; upstream files belong to orig.
tar -tJf "$dtar" >"$build_dir/.debian-tar.list"
if ! awk '!/^debian\// { print "unexpected entry outside debian/: " $0; bad = 1 }
          END { exit bad ? 1 : 0 }' "$build_dir/.debian-tar.list"; then
    rm -f "$build_dir/.debian-tar.list"
    die "$dtar contains files outside debian/; the orig tarball is not complete"
fi
rm -f "$build_dir/.debian-tar.list"

# Re-extract the generated source package: it must contain both halves.
rm -rf "$roundtrip"
dpkg-source -x "$dsc" "$roundtrip" >"$build_dir/dpkg-source-extract.log" 2>&1 \
    || die "cannot re-extract $dsc; see $build_dir/dpkg-source-extract.log"
for path in debian/control debian/rules core/server/go.mod CMakeLists.txt; do
    [ -e "$roundtrip/$path" ] \
        || die "re-extracted source package is missing $path"
done

# ----------------------------------------------------------------- report ---
cat <<EOF

Prepared source tree:  $tree
Orig tarball:          $orig
  sha256  $(sha256sum "$orig" | awk '{print $1}')
  source  $(if [ "$reused" -eq 1 ]; then echo 'upstream bytes, unchanged'; else echo 'repacked, contents unchanged'; fi)
Source package:        $dsc
  verified by re-extracting it and checking debian/ plus core/server/go.mod

Next steps (no binary build here):
  cd $tree
  dpkg-buildpackage -S -sa -us -uc    # source-only; -sa includes the orig
                                      # tarball on the first upload, then dput
  dpkg-buildpackage -b -us -uc        # local binary build, once reviewed

EOF
