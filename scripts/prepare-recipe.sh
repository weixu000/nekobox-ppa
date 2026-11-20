#!/bin/bash
# Create the source-only staging Git repository for nekobox.recipe.
#
# Usage: scripts/prepare-recipe.sh [--refresh-download] [--output-dir DIR]
#                                  [--packaging-dir DIR]
#
#   --refresh-download   ignore downloads/ and fetch the pinned tarball again
#   --output-dir DIR     staging parent directory (default: build/recipe-upstream)
#   --packaging-dir DIR  also create branch "main" from this reviewed packaging
#                        tree (default: only the upstream branch is created,
#                        because debian/ may still be changing)
#
# The script always:
#   1. verifies downloads/<UPSTREAM_TARBALL> against UPSTREAM_SHA256 from
#      upstream.env;
#   2. extracts that tarball only (never a build/ tree, never a compiled or
#      otherwise mutated source tree), removes any upstream debian/, and drops
#      the few entries Git cannot represent (paths named .git, empty dirs);
#   3. creates an ignored staging repository whose branch and lightweight tag
#      upstream/<version> are one root commit of that tree;
#   4. verifies the committed blobs against a second manifest of the extracted
#      tree and checks that the recipe pins the same version, repository and
#      branches.
#
# Commits are made only in the staging repository, with the packaging identity
# Oblivion W <oblivion.w23@gmail.com>. Nothing is pushed and the outer
# repository is not modified. Push commands are printed for later use.
set -euo pipefail

umask 022

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck disable=SC1091 # upstream.env is a sibling data file, not a library
# shellcheck source=../upstream.env
. "$repo_root/upstream.env"

for var in UPSTREAM_VERSION UPSTREAM_TARBALL UPSTREAM_URL UPSTREAM_SHA256 \
           UPSTREAM_TOP_DIR UPSTREAM_SOURCE_DATE_EPOCH DEBIAN_REVISION; do
    [ -n "${!var:-}" ] || die "upstream.env does not define $var"
done

# Same repository for both recipe branches. lp: is rewritten by
# git-build-recipe to the anonymous https://git.launchpad.net/ URL.
launchpad_repo=lp:~oblivionw26/+git/nekobox-ppa
launchpad_push=git+ssh://oblivionw26@git.launchpad.net/~oblivionw26/+git/nekobox-ppa
source_branch=upstream/$UPSTREAM_VERSION
packaging_branch=main
recipe_version=$UPSTREAM_VERSION-$DEBIAN_REVISION
recipe=$repo_root/nekobox.recipe
ident_name='Oblivion W'
ident_email='oblivion.w23@gmail.com'

refresh=0
output_dir=$repo_root/build/recipe-upstream
packaging_dir=
while [ $# -gt 0 ]; do
    case "$1" in
        --refresh-download) refresh=1 ;;
        --output-dir)
            shift
            [ $# -gt 0 ] || die "--output-dir needs a directory"
            output_dir=$1
            ;;
        --packaging-dir)
            shift
            [ $# -gt 0 ] || die "--packaging-dir needs a directory"
            packaging_dir=$1
            ;;
        -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

for tool in curl sha256sum tar xz git diff find sort xargs awk sed; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done

# ------------------------------------------------------------ recipe check ---
[ -f "$recipe" ] || die "missing recipe: $recipe"

mapfile -t recipe_code < <(
    awk 'NF && $1 !~ /^#/ { print }' "$recipe"
)
[ "${#recipe_code[@]}" -eq 2 ] \
    || die "$recipe must contain exactly two non-comment lines (found ${#recipe_code[@]})"

header_prefix='# git-build-recipe format 0.4 deb-version '
recipe_header=$(sed -n '1p' "$recipe")
case "$recipe_header" in
    "$header_prefix"*) expected_version=${recipe_header#"$header_prefix"} ;;
    *) die "$recipe line 1 must be '# git-build-recipe format 0.4 deb-version <version>'" ;;
esac
[ -n "$expected_version" ] || die "$recipe line 1 has an empty deb-version"
[ "$expected_version" = "$recipe_version" ] \
    || die "$recipe pins version $expected_version, expected $recipe_version from upstream.env"

[ "${recipe_code[0]}" = "$launchpad_repo $source_branch" ] \
    || die "recipe source line must be '$launchpad_repo $source_branch', got '${recipe_code[0]}'"
[ "${recipe_code[1]}" = "nest-part packaging $launchpad_repo debian debian $packaging_branch" ] \
    || die "recipe packaging line must nest debian/ from $packaging_branch, got '${recipe_code[1]}'"

# ---------------------------------------------------------------- download ---
cache_dir=$repo_root/downloads
tarball=$cache_dir/$UPSTREAM_TARBALL
mkdir -p "$output_dir" "$cache_dir"

if [ "$refresh" -eq 1 ]; then
    rm -f "$tarball"
fi
if [ ! -f "$tarball" ]; then
    note "downloading $UPSTREAM_URL"
    tmp_tarball=$tarball.part
    curl --fail --location --retry 3 --retry-delay 2 --output "$tmp_tarball" \
        "$UPSTREAM_URL" \
        || die "download failed (set http_proxy/https_proxy when the network needs a proxy)"
    mv -f "$tmp_tarball" "$tarball"
else
    note "using cached $tarball"
fi
[ ! -L "$tarball" ] || die "refusing symlinked tarball: $tarball"

note "verifying sha256"
actual=$(sha256sum "$tarball" | awk '{ print $1 }')
[ "$actual" = "$UPSTREAM_SHA256" ] \
    || die "sha256 mismatch for $tarball: expected $UPSTREAM_SHA256, got $actual"

# ----------------------------------------------------------------- extract ---
tmp=$(mktemp -d "${TMPDIR:-/tmp/opencode}/nekobox-recipe.XXXXXX")
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

note "extracting the verified release tarball"
mkdir -p "$tmp/extract"
tar --no-same-owner -xJf "$tarball" -C "$tmp/extract"
source_tree=$tmp/extract/$UPSTREAM_TOP_DIR
[ -d "$source_tree" ] || die "tarball has no top-level directory $UPSTREAM_TOP_DIR"
[ ! -e "$source_tree/.git" ] || die "upstream tarball unexpectedly contains .git"
if [ -e "$source_tree/debian" ]; then
    note "discarding upstream debian/ (packaging comes from branch $packaging_branch)"
    rm -rf "$source_tree/debian"
fi

# Git refuses to store paths named .git. The release tarball carries two
# broken submodule pointers (cpr and qjs) into a .git/modules directory that
# is not in the tarball; they are metadata, not source. Drop and record them.
excluded_paths=()
while IFS= read -r -d '' git_path; do
    rel=${git_path#"$source_tree"/}
    excluded_paths+=("$rel")
    note "dropping $rel (Git cannot store a path named .git)"
    rm -rf -- "$git_path"
done < <(find "$source_tree" -mindepth 2 -name .git -print0)

# Git cannot store empty directories either. Drop and record them so the
# commit can be verified byte-for-byte against the extracted tree.
while IFS= read -r -d '' empty_dir; do
    rel=${empty_dir#"$source_tree"/}
    excluded_paths+=("$rel/")
    note "dropping empty directory $rel/ (Git cannot store empty directories)"
    rmdir -- "$empty_dir"
done < <(find "$source_tree" -mindepth 1 -depth -type d -empty -print0)

excluded_text=
if [ "${#excluded_paths[@]}" -gt 0 ]; then
    excluded_text=$(printf '%s\n' "${excluded_paths[@]}" | LC_ALL=C sort)
fi

# ------------------------------------------------------------------ stage ---
stage=$output_dir/nekobox-ppa
if [ -e "$stage" ]; then
    [ -d "$stage/.git" ] || die "refusing to replace non-repository path: $stage"
    note "replacing previous staging repository $stage"
    rm -rf "$stage"
fi

note "creating staging repository $stage"
mkdir -p "$stage"
git init -q "$stage"
git -C "$stage" symbolic-ref HEAD "refs/heads/$source_branch"
git -C "$stage" config user.name "$ident_name"
git -C "$stage" config user.email "$ident_email"
git -C "$stage" config commit.gpgsign false
git -C "$stage" config tag.gpgsign false
cp -a "$source_tree/." "$stage/"
git -C "$stage" add -f -A -- .

GIT_AUTHOR_NAME=$ident_name GIT_AUTHOR_EMAIL=$ident_email \
GIT_COMMITTER_NAME=$ident_name GIT_COMMITTER_EMAIL=$ident_email \
GIT_AUTHOR_DATE="@$UPSTREAM_SOURCE_DATE_EPOCH +0000" \
GIT_COMMITTER_DATE="@$UPSTREAM_SOURCE_DATE_EPOCH +0000" \
git -C "$stage" commit -q --no-gpg-sign -F - <<EOF
Import upstream $UPSTREAM_VERSION from the official release tarball

Source: $UPSTREAM_URL
Tarball: $UPSTREAM_TARBALL
SHA256: $UPSTREAM_SHA256
Top-level directory: $UPSTREAM_TOP_DIR
Prepared by: scripts/prepare-recipe.sh
$(if [ -n "$excluded_text" ]; then printf '\nExcluded (cannot be represented in Git):\n%s' "$excluded_text"; fi)
EOF

git -C "$stage" tag "$source_branch" HEAD

# ------------------------------------------------------------- validation ---
entry_manifest() {
    local dir=$1
    (
        cd "$dir" || exit 1
        find . -mindepth 1 ! -path './.git' ! -path './.git/*' \
            -printf '%m\t%y\t%P\t%l\n' | LC_ALL=C sort
        find . -type f ! -path './.git/*' -print0 \
            | LC_ALL=C sort -z | xargs -0 -r sha256sum
    )
}

note "verifying the commit contains exactly the extracted upstream tree"
source_commit=$(git -C "$stage" rev-parse "refs/heads/$source_branch")
tag_commit=$(git -C "$stage" rev-parse "refs/tags/$source_branch")
[ "$source_commit" = "$tag_commit" ] \
    || die "branch and tag $source_branch point to different commits"

if ! diff -u <(entry_manifest "$source_tree") <(entry_manifest "$stage"); then
    die "staging tree differs from the verified extracted tree"
fi

committed_paths=$(git -C "$stage" ls-tree -r -z --name-only "$source_commit" \
    | tr '\0' '\n' | LC_ALL=C sort)
expected_paths=$(cd "$source_tree" && find . -mindepth 1 \
    \( -type f -o -type l \) -printf '%P\n' | LC_ALL=C sort)
[ "$committed_paths" = "$expected_paths" ] \
    || die "commit $source_commit does not contain the extracted file list"

# Check the committed blobs themselves, not only the worktree: attributes or
# filters could otherwise change line endings while leaving git status clean.
checkout_tree=$tmp/checkout-tree
mkdir -p "$checkout_tree"
git -C "$stage" -c core.autocrlf=false --work-tree="$checkout_tree" \
    checkout-index -a --prefix="$checkout_tree/" >/dev/null
if ! diff -u <(entry_manifest "$source_tree") <(entry_manifest "$checkout_tree"); then
    die "committed blobs differ from the verified extracted tree"
fi

status=$(git -C "$stage" status --porcelain --ignored --untracked-files=all)
[ -z "$status" ] || die "staging worktree is not clean after the commit:
$status"

if git -C "$stage" ls-tree -r --name-only "$source_commit" | grep -q '^debian/'; then
    die "upstream branch unexpectedly contains debian/"
fi

# --------------------------------------------------- optional packaging branch ---
if [ -n "$packaging_dir" ]; then
    [ -d "$packaging_dir/debian" ] || die "$packaging_dir has no debian/ directory"
    changelog_version=$(sed -n '1s/^[^(]*(\([^)]*\)).*/\1/p' "$packaging_dir/debian/changelog")
    [ "$changelog_version" = "$recipe_version" ] \
        || die "debian/changelog is $changelog_version but the recipe pins $recipe_version"

    note "importing packaging from $packaging_dir as branch $packaging_branch"
    packtmp=$tmp/packaging
    mkdir -p "$packtmp"
    tar -C "$packaging_dir" --exclude=./.git --exclude=./build \
        --exclude=./downloads -cf - . | tar -C "$packtmp" -xf -

    index_file=$tmp/main.index
    (
        cd "$packtmp"
        GIT_DIR=$stage/.git GIT_WORK_TREE=$packtmp GIT_INDEX_FILE=$index_file \
            git add -f -A -- .
    )
    packaging_tree=$(GIT_DIR=$stage/.git GIT_INDEX_FILE=$index_file git write-tree)
    packaging_commit=$(printf 'Import packaging tree for %s\n' "$recipe_version" \
        | GIT_AUTHOR_NAME=$ident_name GIT_AUTHOR_EMAIL=$ident_email \
          GIT_COMMITTER_NAME=$ident_name GIT_COMMITTER_EMAIL=$ident_email \
          GIT_AUTHOR_DATE="@$(date -u +%s) +0000" \
          GIT_COMMITTER_DATE="@$(date -u +%s) +0000" \
          git --git-dir="$stage/.git" commit-tree "$packaging_tree")
    git -C "$stage" update-ref "refs/heads/$packaging_branch" "$packaging_commit"

    if ! git -C "$stage" show "$packaging_commit:debian/control" >/dev/null 2>&1; then
        die "imported branch $packaging_branch has no debian/control"
    fi
fi

# ---------------------------------------------------------------- manifest ---
manifest=$output_dir/MANIFEST
cat >"$manifest" <<EOF
recipe=$recipe
recipe_version=$recipe_version
launchpad_repo=$launchpad_repo
launchpad_push=$launchpad_push
tarball=$tarball
tarball_sha256=$UPSTREAM_SHA256
source_branch=$source_branch
source_commit=$source_commit
source_tree=$(git -C "$stage" rev-parse "$source_commit^{tree}")
excluded_paths=$(printf '%s' "$excluded_text" | tr '\n' ' ')
packaging_branch=$packaging_branch
packaging_commit=$(git -C "$stage" rev-parse --verify --quiet "refs/heads/$packaging_branch" || true)
EOF

cat <<EOF

Staging repository:     $stage
Manifest:               $manifest
Recipe:                 $recipe (version $recipe_version)
Upstream branch/tag:    $source_branch
Upstream commit:        $source_commit
Upstream tree:          $(git -C "$stage" rev-parse "$source_commit^{tree}")
EOF
if [ -n "$excluded_text" ]; then
    printf 'Excluded (not representable in Git): %s\n' "$(printf '%s' "$excluded_text" | tr '\n' ' ')"
fi
cat <<EOF
Packaging branch:       $(if git -C "$stage" rev-parse --verify --quiet "refs/heads/$packaging_branch" >/dev/null; then echo "$packaging_branch ($(git -C "$stage" rev-parse --short "refs/heads/$packaging_branch"))"; else echo "not created (pass --packaging-dir once debian/ is stable)"; fi)

Nothing has been pushed. When the Launchpad repository
  https://code.launchpad.net/~oblivionw26/+git/nekobox-ppa
exists and you are ready:

  git -C $stage push $launchpad_push refs/heads/$source_branch:refs/heads/$source_branch
  git -C $stage push $launchpad_push refs/tags/$source_branch:refs/tags/$source_branch
EOF

if git -C "$stage" rev-parse --verify --quiet "refs/heads/$packaging_branch" >/dev/null; then
    cat <<EOF
  git -C $stage push $launchpad_push refs/heads/$packaging_branch:refs/heads/$packaging_branch
EOF
else
    cat <<EOF
  # Push branch $packaging_branch from the real packaging repository once its
  # first commit exists; the recipe only reads its debian/ subtree.
EOF
fi

cat <<EOF

Then create the recipe (do NOT tick "Build daily" yet), paste nekobox.recipe,
select the PPA and request one build by hand. Validate locally first with
git-build-recipe in a disposable container.
EOF
