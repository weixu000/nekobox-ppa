#!/bin/bash
# Prepare the ignored build/ tree for this source package.
#
# Usage: scripts/prepare-source.sh [--refresh-download] [--repack]
#                                  [--orig-file PATH --orig-sha256 HEX]
#
#   --refresh-download  ignore the copy in downloads/ and fetch again
#   --repack            always repack the orig tarball under nekobox-<version>/
#                       instead of reusing the upstream tarball bytes
#   --orig-file PATH    use this already-published orig tarball instead of the
#                       pinned upstream download.  This repository's policy is
#                       to reuse the archived bytes for an upstream version
#                       when a packaging revision is uploaded (a different
#                       compression name is technically possible, but reuse is
#                       intentional); the caller verifies them against the
#                       published .dsc and this re-checks the bytes here.
#   --orig-sha256 HEX   required with --orig-file
#
# Steps:
#   1. download the pinned upstream release into downloads/ (cached) and
#      verify UPSTREAM_SHA256 from upstream.env; with --orig-file, verify the
#      supplied archived orig instead and skip the upstream download;
#   2. unpack it under build/nekobox-<version>/ and overlay ./debian/;
#   3. create build/nekobox_<version>.orig.tar.*: the upstream bytes are
#      reused unchanged when dpkg-source accepts them, otherwise the same file
#      contents are repacked under the Debian top-level directory name.  With
#      --orig-file the supplied bytes are copied unchanged;
#   4. run dpkg-source -b, then re-extract the generated source package to
#      prove it is complete (debian/ and upstream sources both present).
#
# Only the pinned release (or the explicitly supplied archived orig) is used
# as source. reference/ is a comparison clone and is never read by this script.
# No binary package is built here.
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
orig_file=
orig_sha256=
while [ $# -gt 0 ]; do
    case "$1" in
        --refresh-download) refresh=1 ;;
        --repack) force_repack=1 ;;
        --orig-file)
            shift
            [ $# -gt 0 ] || die "--orig-file needs a path"
            orig_file=$1
            ;;
        --orig-sha256)
            shift
            [ $# -gt 0 ] || die "--orig-sha256 needs a value"
            orig_sha256=$1
            ;;
        -h|--help) sed -n '2,27p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

if [ -n "$orig_file" ] && [ -z "$orig_sha256" ]; then
    die "--orig-file requires --orig-sha256"
fi
if [ -z "$orig_file" ] && [ -n "$orig_sha256" ]; then
    die "--orig-sha256 is only valid with --orig-file"
fi

for tool in curl sha256sum tar xz dpkg-source; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done

cache_dir=$repo_root/downloads
build_dir=$repo_root/build
tarball=$cache_dir/$UPSTREAM_TARBALL
tree=$build_dir/nekobox-$UPSTREAM_VERSION
stage=$build_dir/.stage-$UPSTREAM_VERSION
roundtrip=$build_dir/.roundtrip
source_log=$build_dir/dpkg-source.log
safe_orig=

cleanup() {
    rm -rf "$stage" "$roundtrip"
    if [ -n "$safe_orig" ]; then rm -f "$safe_orig"; fi
}
trap cleanup EXIT

mkdir -p "$cache_dir" "$build_dir"

# ---------------------------------------------------------------- download ---
if [ -n "$orig_file" ]; then
    [ -f "$orig_file" ] || die "archived orig tarball not found: $orig_file"
    note "verifying archived orig $orig_file"
    actual=$(sha256sum "$orig_file" | awk '{print $1}')
    [ "$actual" = "$orig_sha256" ] \
        || die "sha256 mismatch for $orig_file: expected $orig_sha256, got $actual"
    case "$orig_file" in
        *.orig.tar.xz) orig_ext=.tar.xz ;;
        *.orig.tar.gz) orig_ext=.tar.gz ;;
        *.orig.tar.bz2) orig_ext=.tar.bz2 ;;
        *.orig.tar.lzma) orig_ext=.tar.lzma ;;
        *) die "unrecognised orig tarball extension: $orig_file" ;;
    esac
    # The input may live at build/nekobox_<version>.orig.tar.gz, which
    # drop_source_artifacts() removes.  Keep a verified private copy first so
    # the natural CLI path cannot delete its own input.
    safe_orig=$(mktemp "$build_dir/.archived-orig.XXXXXX")
    cp -f "$orig_file" "$safe_orig"
    orig_file=$safe_orig
    orig=$build_dir/nekobox_$UPSTREAM_VERSION.orig$orig_ext
else
    orig=$build_dir/nekobox_$UPSTREAM_VERSION.orig.tar.xz
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
fi

# ----------------------------------------------------------------- unpack ---
note "unpacking source"
rm -rf "$stage" "$tree"
mkdir -p "$stage"
if [ -n "$orig_file" ]; then
    tar -xf "$orig_file" -C "$stage"
    mapfile -t tops < <(tar -tf "$orig_file" | sed -e 's#^\./##' -e 's#/.*##' | LC_ALL=C sort -u)
    [ "${#tops[@]}" -eq 1 ] && [ -n "${tops[0]}" ] \
        || die "archived orig does not have exactly one top-level directory"
    orig_top=${tops[0]}
else
    tar -xJf "$tarball" -C "$stage"
    orig_top=$UPSTREAM_TOP_DIR
fi
[ -d "$stage/$orig_top" ] \
    || die "tarball has no top-level directory $orig_top"
if [ -e "$stage/$orig_top/debian" ]; then
    note "discarding upstream debian/ (packaging comes from this repository)"
    rm -rf "$stage/$orig_top/debian"
fi
if [ "$orig_top" != "nekobox-$UPSTREAM_VERSION" ]; then
    mv "$stage/$orig_top" "$stage/nekobox-$UPSTREAM_VERSION"
fi

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
    rm -f "$build_dir"/*.dsc "$build_dir"/*.debian.tar.* \
          "$build_dir"/nekobox_"$UPSTREAM_VERSION".orig.tar.*
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
source_kind='upstream bytes, unchanged'
drop_source_artifacts
if [ -n "$orig_file" ]; then
    note "installing the archived orig bytes unchanged as $orig"
    cp -f "$orig_file" "$orig"
    build_source || die "dpkg-source -b failed with the archived orig; see $source_log"
    reused=1
    source_kind='archived orig bytes, unchanged'
elif [ "$force_repack" -eq 0 ]; then
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
    source_kind='repacked, contents unchanged'
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
  source  $source_kind
Source package:        $dsc
  verified by re-extracting it and checking debian/ plus core/server/go.mod

Next steps (no binary build here):
  cd $tree
  dpkg-buildpackage -S -sa -us -uc    # source-only; -sa includes the orig
                                      # tarball on the first upload, then dput
  dpkg-buildpackage -b -us -uc        # local binary build, once reviewed

EOF
