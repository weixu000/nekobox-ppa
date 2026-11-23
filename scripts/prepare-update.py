#!/usr/bin/env python3
"""Apply a discovered stable upstream release to the packaging metadata.

This is the deterministic first step of the GitHub Actions release pipeline:

  1. read and validate the JSON produced by scripts/check-upstream.py;
  2. download the unified source tarball and verify its SHA-256 (the GitHub
     asset digest is required for unattended runs);
  3. inspect the archive members without extracting them;
  4. update upstream.env, debian/changelog and nekobox.recipe together.

It does not commit, push, build, or regenerate licence notices.  The workflow
runs scripts/prepare-source.sh and scripts/collect-notices.py afterwards, then
lets every supported series build the resulting tree offline.

Usage:
    scripts/prepare-update.py --check-json build/update-check.json
    scripts/prepare-update.py --check-json check.json --tarball downloads/x.tar.xz

Exit codes: 0 success, 2 usage/configuration error, 3 network error,
4 malformed input, 5 verification failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
ASSET_RE = re.compile(r"^nekobox-unified-source-([^/]+)\.tar\.xz$")
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+~:-]{0,127}$")
RELEASE_URL_RE = re.compile(
    r"^https://github\.com/([^/\s]+)/([^/\s]+)/releases/download/"
    r"([^/\s]+)/([^/\s]+)$"
)
DIGEST_RE = re.compile(r"^sha256:([0-9a-fA-F]{64})$")
ENV_KEYS = (
    "UPSTREAM_VERSION",
    "UPSTREAM_TARBALL",
    "UPSTREAM_URL",
    "UPSTREAM_SHA256",
    "UPSTREAM_TOP_DIR",
    "UPSTREAM_SOURCE_DATE_EPOCH",
)
CHANGELOG_VERSION_RE = re.compile(r"^[^(]+\(([^)]+)\)")
MAX_DOWNLOAD = 2 * 1024 * 1024 * 1024
CHUNK = 1024 * 1024


class PrepareError(Exception):
    exit_code = 1


class UsageError(PrepareError):
    exit_code = 2


class NetworkError(PrepareError):
    exit_code = 3


class InputError(PrepareError):
    exit_code = 4


class VerificationError(PrepareError):
    exit_code = 5


# --------------------------------------------------------------------------
# env and metadata
# --------------------------------------------------------------------------


def read_env(path: Path) -> dict[str, str]:
    """Read the simple KEY=VALUE file used by upstream.env."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc}") from exc
    values: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            raise UsageError(f"{path}:{lineno}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise UsageError(f"{path}:{lineno}: invalid variable name {key!r}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key] = value
    return values


def require(values: dict[str, str], key: str) -> str:
    value = values.get(key, "")
    if not value:
        raise UsageError(f"upstream.env does not define {key}")
    return value


def set_env_value(text: str, key: str, value: str) -> str:
    pattern = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise UsageError(f"upstream.env must define {key} exactly once")
    return pattern.sub(f"{key}={value}", text, count=1)


def update_env_text(text: str, values: dict[str, str]) -> str:
    for key in ENV_KEYS:
        text = set_env_value(text, key, values[key])
    return text


def changelog_version(text: str) -> str | None:
    first = text.splitlines()[0] if text.splitlines() else ""
    match = CHANGELOG_VERSION_RE.match(first)
    return match.group(1) if match else None


def prepend_changelog(text: str, version: str, distribution: str, body: str,
                      date: str) -> str:
    entry = (
        f"nekobox ({version}) {distribution}; urgency=medium\n\n"
        f"{body.rstrip()}\n\n"
        f" -- Oblivion W <oblivion.w23@gmail.com>  {date}\n\n"
    )
    return entry + text


def update_recipe_text(text: str, old_version: str, new_version: str,
                       revision: str) -> str:
    header = "# git-build-recipe format 0.4 deb-version "
    lines = text.splitlines()
    if not lines or not lines[0].startswith(header):
        raise UsageError(
            "nekobox.recipe line 1 must start with "
            f"{header!r}"
        )
    if old_version not in text:
        raise UsageError(
            f"nekobox.recipe does not mention the pinned version {old_version}"
        )
    updated = text.replace(old_version, new_version)
    lines = updated.splitlines()
    expected_version = f"{new_version}-{revision}"
    lines[0] = header + expected_version
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# release inputs
# --------------------------------------------------------------------------


def parse_iso_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise InputError("candidate.released_at is missing or empty")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise InputError(f"candidate.released_at is not ISO 8601: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def release_epoch(value: Any) -> int:
    return int(parse_iso_timestamp(value).timestamp())


def load_candidate(path: Path, current_version: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise InputError("check JSON must be an object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise InputError(
            f"unsupported check schema_version {payload.get('schema_version')!r}"
        )
    if payload.get("status") != "update-available":
        raise UsageError(
            "check status is not update-available; nothing to prepare"
        )
    current = payload.get("current")
    if not isinstance(current, dict) or current.get("version") != current_version:
        raise InputError(
            "check JSON was produced for a different pinned version"
        )
    candidate = payload.get("candidate")
    if not isinstance(candidate, dict):
        raise InputError("check JSON has no candidate")

    version = candidate.get("version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise InputError(f"candidate.version is not a usable Debian version: {version!r}")
    asset_name = candidate.get("asset_name")
    if not isinstance(asset_name, str) or not ASSET_RE.fullmatch(asset_name):
        raise InputError(f"candidate.asset_name is not the unified source asset: {asset_name!r}")
    if ASSET_RE.fullmatch(asset_name).group(1) != version:  # type: ignore[union-attr]
        raise InputError("candidate.asset_name does not match candidate.version")

    asset_url = candidate.get("asset_url")
    if not isinstance(asset_url, str):
        raise InputError("candidate.asset_url is missing")
    match = RELEASE_URL_RE.match(asset_url)
    if not match:
        raise InputError(f"candidate.asset_url is not a GitHub release URL: {asset_url}")
    _owner, _repo, tag, url_asset = match.groups()
    if url_asset != asset_name:
        raise InputError("candidate.asset_url names a different asset")
    if tag != version and tag != f"v{version}":
        raise InputError("candidate.asset_url tag does not match candidate.version")

    digest = candidate.get("digest")
    if digest is not None:
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            raise InputError(
                "candidate.digest is not a sha256:<hex> value; refusing to trust it"
            )
        digest = digest.split(":", 1)[1].lower()

    size = candidate.get("size")
    if size is not None and (not isinstance(size, int) or size <= 0):
        raise InputError("candidate.size is not a positive integer")

    return {
        "version": version,
        "asset_name": asset_name,
        "asset_url": asset_url,
        "digest": digest,
        "size": size,
        "released_at": candidate.get("released_at"),
        "epoch": release_epoch(candidate.get("released_at")),
        "tag": tag,
    }


def version_is_newer(current: str, candidate: str) -> bool:
    try:
        proc = subprocess.run(
            ["dpkg", "--compare-versions", current, "lt", candidate],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise UsageError("required tool not found: dpkg") from exc
    if proc.returncode not in (0, 1):
        raise UsageError(
            f"dpkg cannot compare {current!r} and {candidate!r}: "
            f"{proc.stderr.strip()}"
        )
    return proc.returncode == 0


# --------------------------------------------------------------------------
# download and archive checks
# --------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, destination: Path, timeout: float = 120.0) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise VerificationError(f"refusing symlinked download path {destination}")
    tmp = destination.with_name(destination.name + ".part")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "nekobox-ppa-prepare-update/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            length = response.headers.get("Content-Length")
            try:
                length_value = int(length) if length is not None else None
            except ValueError:
                length_value = None
            if length_value is not None and length_value > MAX_DOWNLOAD:
                raise VerificationError(
                    f"refusing download larger than {MAX_DOWNLOAD} bytes"
                )
            total = 0
            with tmp.open("wb") as handle:
                while True:
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOWNLOAD:
                        raise VerificationError(
                            f"download exceeded {MAX_DOWNLOAD} bytes"
                        )
                    handle.write(chunk)
        os.replace(tmp, destination)
    except urllib.error.HTTPError as exc:
        tmp.unlink(missing_ok=True)
        raise NetworkError(f"HTTP {exc.code} downloading {url}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        tmp.unlink(missing_ok=True)
        reason = getattr(exc, "reason", exc)
        raise NetworkError(f"cannot download {url}: {reason}") from exc


def archive_top_dir(path: Path) -> str:
    """Inspect member names safely and return the single top-level directory."""
    try:
        with tarfile.open(path, "r:xz") as archive:
            members = archive.getmembers()
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise VerificationError(f"{path} is not a readable xz tar archive: {exc}") from exc
    if not members:
        raise VerificationError(f"{path} is empty")
    tops: set[str] = set()
    regular = 0
    for member in members:
        name = member.name
        if not name or name.startswith("/"):
            raise VerificationError(f"archive contains an absolute path: {name!r}")
        parts = PurePosixPath(name).parts
        if any(part in ("..", ".") for part in parts):
            raise VerificationError(f"archive contains an unsafe path: {name!r}")
        tops.add(parts[0])
        if member.isfile():
            regular += 1
        if member.issym() or member.islnk():
            target = member.linkname
            if (
                not target
                or target.startswith("/")
                or ".." in PurePosixPath(target).parts
            ):
                raise VerificationError(
                    f"archive contains an unsafe link {name!r} -> {target!r}"
                )
        if member.isdev() or member.isfifo():
            raise VerificationError(
                f"archive contains a device or FIFO: {name!r}"
            )
    if len(tops) != 1:
        raise VerificationError(
            f"archive must have exactly one top-level directory, found {sorted(tops)}"
        )
    if regular == 0:
        raise VerificationError("archive contains no regular files")
    return tops.pop()


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def rfc2822_now() -> str:
    return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")


def run(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(args.repo_root).resolve()
    env_path = repo / "upstream.env"
    changelog_path = repo / "debian" / "changelog"
    recipe_path = repo / "nekobox.recipe"

    env = read_env(env_path)
    current_version = require(env, "UPSTREAM_VERSION")
    revision = require(env, "DEBIAN_REVISION")
    distribution = require(env, "DEBIAN_DISTRIBUTION")
    candidate = load_candidate(Path(args.check_json), current_version)
    version = candidate["version"]
    if not version_is_newer(current_version, version):
        raise UsageError(
            f"candidate {version} is not newer than pinned {current_version}"
        )
    if candidate["digest"] is None and not args.allow_missing_digest:
        raise VerificationError(
            "GitHub supplied no asset digest; rerun with --allow-missing-digest "
            "only after verifying the tarball by another published checksum"
        )

    download_dir = Path(args.download_dir).resolve()
    tarball = download_dir / candidate["asset_name"]
    if args.tarball:
        tarball = Path(args.tarball).resolve()
        if not tarball.is_file():
            raise UsageError(f"--tarball does not exist: {tarball}")
    else:
        valid_existing = tarball.is_file() and not tarball.is_symlink()
        if valid_existing:
            actual = sha256_file(tarball)
            valid_existing = (
                actual == candidate["digest"]
                if candidate["digest"]
                else tarball.stat().st_size == candidate["size"]
            )
        if not valid_existing:
            download(candidate["asset_url"], tarball)

    if tarball.is_symlink():
        raise VerificationError(f"refusing symlinked tarball {tarball}")
    actual_sha = sha256_file(tarball)
    if candidate["digest"] and actual_sha != candidate["digest"]:
        raise VerificationError(
            f"sha256 mismatch for {tarball.name}: expected "
            f"{candidate['digest']}, got {actual_sha}"
        )
    if candidate["size"] is not None and tarball.stat().st_size != candidate["size"]:
        raise VerificationError(
            f"size mismatch for {tarball.name}: expected {candidate['size']}, "
            f"got {tarball.stat().st_size}"
        )

    top_dir = archive_top_dir(tarball)
    expected_top = candidate["asset_name"][: -len(".tar.xz")]
    if top_dir != expected_top:
        raise VerificationError(
            f"archive top-level directory is {top_dir!r}, expected {expected_top!r}"
        )

    base_version = f"{version}-{revision}"
    env_values = {
        "UPSTREAM_VERSION": version,
        "UPSTREAM_TARBALL": candidate["asset_name"],
        "UPSTREAM_URL": candidate["asset_url"],
        "UPSTREAM_SHA256": actual_sha,
        "UPSTREAM_TOP_DIR": top_dir,
        "UPSTREAM_SOURCE_DATE_EPOCH": str(candidate["epoch"]),
    }
    new_env = update_env_text(env_path.read_text(encoding="utf-8"), env_values)

    changelog_text = changelog_path.read_text(encoding="utf-8")
    if changelog_version(changelog_text) != base_version:
        release_page = (
            candidate["asset_url"].split("/download/", 1)[0]
            + "/tag/"
            + candidate["tag"]
        )
        body = (
            f"  * New upstream stable release {version}.\n"
            f"    {release_page}\n"
        )
        changelog_text = prepend_changelog(
            changelog_text, base_version, distribution, body, rfc2822_now()
        )

    recipe_text = update_recipe_text(
        recipe_path.read_text(encoding="utf-8"),
        current_version,
        version,
        revision,
    )

    # Keep the package version and recipe header from drifting apart.
    first_changelog_version = changelog_version(changelog_text)
    first_recipe = recipe_text.splitlines()[0]
    if first_changelog_version != base_version:
        raise VerificationError(
            f"internal error: changelog is {first_changelog_version}, "
            f"expected {base_version}"
        )
    if not first_recipe.endswith(base_version):
        raise VerificationError(
            f"internal error: recipe header does not pin {base_version}"
        )

    env_path.write_text(new_env, encoding="utf-8")
    changelog_path.write_text(changelog_text, encoding="utf-8")
    recipe_path.write_text(recipe_text, encoding="utf-8")

    metadata = {
        "schema_version": SCHEMA_VERSION,
        "current_version": current_version,
        "version": version,
        "base_version": base_version,
        "revision": revision,
        "distribution": distribution,
        "asset_name": candidate["asset_name"],
        "asset_url": candidate["asset_url"],
        "sha256": actual_sha,
        "size": tarball.stat().st_size,
        "top_dir": top_dir,
        "released_at": candidate["released_at"],
        "source_date_epoch": candidate["epoch"],
        "tarball": str(tarball),
    }
    metadata_path = Path(args.metadata)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prepare-update.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--check-json", required=True, help="scripts/check-upstream.py output")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--download-dir", default=None, help="default: <repo-root>/downloads")
    parser.add_argument("--tarball", help="use this already-downloaded tarball")
    parser.add_argument("--metadata", default=None, help="default: <repo-root>/build/release.json")
    parser.add_argument(
        "--allow-missing-digest",
        action="store_true",
        help="accept an asset without a GitHub sha256 digest (manual only)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(args.repo_root).resolve()
    args.repo_root = str(repo)
    if args.download_dir is None:
        args.download_dir = str(repo / "downloads")
    if args.metadata is None:
        args.metadata = str(repo / "build" / "release.json")
    try:
        metadata = run(args)
    except PrepareError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    print(
        f"prepared {metadata['version']} ({metadata['base_version']}) "
        f"sha256={metadata['sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
