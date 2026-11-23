#!/bin/bash
# Validate nekobox.recipe with git-build-recipe, without Launchpad access.
#
# Usage: scripts/validate-recipe.sh [--series noble,resolute,stonking]
#
# scripts/prepare-recipe.sh creates a staging repository from the pinned
# tarball and the current debian/ tree.  A temporary copy of the recipe points
# at that repository instead of lp:~oblivionw26/..., then git-build-recipe
# assembles and checks the source package for each supported series using the
# same --append-version suffix Launchpad applies.  Nothing is pushed.
set -euo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }

series_csv=noble,resolute,stonking
while [ $# -gt 0 ]; do
    case "$1" in
        --series) shift; series_csv=${1:-} ;;
        -h|--help) sed -n '2,11p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck disable=SC1091 # upstream.env is a sibling data file, not a library
# shellcheck source=../upstream.env
. "$repo_root/upstream.env"
base_version=$UPSTREAM_VERSION-$DEBIAN_REVISION

for tool in git git-build-recipe dpkg-source tar xz; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done

tmp=$(mktemp -d "${TMPDIR:-/tmp}/nekobox-recipe-validate.XXXXXX")
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

note "creating the staging repository"
"$repo_root/scripts/prepare-recipe.sh" \
    --packaging-dir "$repo_root" \
    --output-dir "$tmp/recipe" >"$tmp/prepare-recipe.log" 2>&1 \
    || { cat "$tmp/prepare-recipe.log" >&2; die "prepare-recipe.sh failed"; }
stage=$tmp/recipe/nekobox-ppa
[ -d "$stage/.git" ] || die "prepare-recipe.sh did not create a staging repository"

local_recipe=$tmp/nekobox.recipe.local
sed "s#lp:~oblivionw26/+git/nekobox-ppa#$stage#g" \
    "$repo_root/nekobox.recipe" >"$local_recipe"

suffix_for() {
    case "$1" in
        noble) echo '~ubuntu24.04.1' ;;
        resolute) echo '~ubuntu26.04.1' ;;
        stonking) echo '~ubuntu26.10.1' ;;
        *) die "no Launchpad version suffix known for $1" ;;
    esac
}

IFS=, read -r -a series_list <<<"$series_csv"
for series in "${series_list[@]}"; do
    [ -n "$series" ] || continue
    suffix=$(suffix_for "$series")
    expected=$base_version$suffix
    work=$tmp/work-$series
    mkdir -p "$work"
    note "assembling the source package for $series ($expected)"
    if ! ( cd "$tmp" && git-build-recipe --no-build --safe \
            --distribution "$series" --append-version "$suffix" \
            "$local_recipe" "$work" ) >"$tmp/git-build-recipe-$series.log" 2>&1; then
        cat "$tmp/git-build-recipe-$series.log" >&2
        die "git-build-recipe failed for $series"
    fi

    source_tree=$(find "$work" -mindepth 1 -maxdepth 1 -type d \
        ! -name 'nekobox_*' -print -quit)
    [ -n "$source_tree" ] || die "git-build-recipe produced no source tree for $series"
    for path in debian/control debian/rules core/server/go.mod CMakeLists.txt; do
        [ -e "$source_tree/$path" ] \
            || die "$series source package is missing $path"
    done
    actual=$(sed -n '1s/^[^(]*(\([^)]*\)).*/\1/p' "$source_tree/debian/changelog")
    [ "$actual" = "$expected" ] \
        || die "$series changelog version is $actual, expected $expected"

    # Force dpkg-source to produce the upload form and reject a silent native
    # fallback (which would happen if the upstream tag were missing).
    if ! ( cd "$source_tree" && dpkg-source -b . ) >"$tmp/dpkg-source-$series.log" 2>&1; then
        cat "$tmp/dpkg-source-$series.log" >&2
        die "dpkg-source failed for $series"
    fi
    dsc=$(find "$work" -maxdepth 1 -name '*.dsc' -print -quit)
    [ -n "$dsc" ] || die "$series produced no .dsc"
    format=$(sed -n 's/^Format: //p' "$dsc")
    [ "$format" = "3.0 (quilt)" ] \
        || die "$series source format is '$format', expected 3.0 (quilt)"
    orig=$(find "$work" -maxdepth 1 -name "nekobox_${UPSTREAM_VERSION}.orig.tar.*" -print -quit)
    [ -n "$orig" ] || die "$series .dsc has no upstream orig tarball"
    grep -q "nekobox_${UPSTREAM_VERSION}.orig.tar" "$dsc" \
        || die "$series .dsc does not reference the orig tarball"
    grep -q 'nekobox_.*\.debian\.tar\.' "$dsc" \
        || die "$series .dsc does not reference the debian tarball"
    printf 'validated %s: %s (%s)\n' "$series" "$actual" "$format"
done

note "recipe validation passed for $series_csv"
