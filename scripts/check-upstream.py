#!/usr/bin/env python3
"""Read-only discovery of newer NekoBox source releases.

The packaging repository pins one upstream release in upstream.env.  This
command asks GitHub for the project's published releases, ignores drafts and
prereleases, requires the exact unified source tarball
(nekobox-unified-source-<version>.tar.xz), and compares versions with
``dpkg --compare-versions``.  It reports the result as JSON and never
downloads, unpacks or modifies anything.

Usage:
    scripts/check-upstream.py
    scripts/check-upstream.py --env upstream.env --timeout 20
    scripts/check-upstream.py --releases-json tests/fixtures/releases.json
    scripts/check-upstream.py --api-url http://127.0.0.1:8080/releases

--releases-json reads a saved GitHub /releases response instead of using the
network.  --api-url is mainly for mirrors and tests; it conflicts with
--releases-json.  Standard proxy variables (http_proxy, https_proxy,
no_proxy, and their uppercase forms) are honoured by urllib.

Exit codes:
    0  check completed; see "status" in the JSON: "update-available" or
       "up-to-date" (both are successful checks)
    2  usage or configuration error (bad upstream.env, missing dpkg, ...)
    3  network or HTTP error while querying the GitHub API
    4  malformed or unexpected GitHub API response

The JSON "candidate.digest" field is optional release metadata supplied by
GitHub and may be null.  It is not a substitute for verification: after
downloading the tarball, compute its SHA-256 and check it against the
release's published checksum before changing upstream.env.  A candidate with
no digest is still a valid discovery result.

No credentials are read and no authenticated GitHub requests are made.
Unauthenticated API requests are rate limited; a daily check is well within
that limit.
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
ASSET_TEMPLATE = "nekobox-unified-source-{version}.tar.xz"
USER_AGENT = "nekobox-ppa-check-upstream/1"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_PAGES = 20
PAGE_SIZE = 100
RETRYABLE_HTTP_STATUS = {500, 502, 503, 504}
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+~:-]{0,127}$")
RELEASE_URL_RE = re.compile(
    r"^https://github\.com/([^/\s]+)/([^/\s]+)/releases/download/"
    r"([^/\s]+)/([^/\s]+)$"
)
DEFAULT_ENV = Path(__file__).resolve().parent.parent / "upstream.env"


class CheckError(Exception):
    """A failure with a machine-readable kind and a distinct exit code."""

    kind = "error"
    exit_code = 1


class ConfigError(CheckError):
    kind = "config"
    exit_code = 2


class NetworkError(CheckError):
    kind = "network"
    exit_code = 3


class InvalidResponse(CheckError):
    kind = "invalid-response"
    exit_code = 4


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


def read_env_file(path: Path) -> dict[str, str]:
    """Read the simple KEY=VALUE format used by upstream.env.

    This deliberately supports only plain assignments and matching single or
    double quotes.  It does not expand variables, run commands, or otherwise
    behave like a shell, so a data file cannot execute anything.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read env file {path}: {exc}") from exc

    values: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            raise ConfigError(f"{path}:{lineno}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ConfigError(f"{path}:{lineno}: invalid variable name {key!r}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key] = value
    return values


def require(values: dict[str, str], key: str) -> str:
    value = values.get(key, "")
    if not value:
        raise ConfigError(f"upstream.env does not define {key}")
    return value


def parse_release_url(url: str) -> tuple[str, str, str]:
    """Return (owner/repo, tag, asset name) from a GitHub release URL."""
    match = RELEASE_URL_RE.match(url)
    if not match:
        raise ConfigError(
            "UPSTREAM_URL is not a GitHub release download URL: " + url
        )
    owner, repo, tag, asset = match.groups()
    return f"{owner}/{repo}", tag, asset


def release_version(tag: str) -> str | None:
    """Map a release tag to a Debian-comparable version, or None."""
    version = tag[1:] if re.fullmatch(r"v[0-9].*", tag) else tag
    return version if VERSION_RE.fullmatch(version) else None


def check_version(value: str, label: str) -> str:
    if not VERSION_RE.fullmatch(value):
        raise ConfigError(f"{label} is not a usable Debian version: {value!r}")
    return value


# --------------------------------------------------------------------------
# version comparison
# --------------------------------------------------------------------------


def version_lt(left: str, right: str) -> bool:
    """True when left < right according to dpkg, not string ordering."""
    try:
        proc = subprocess.run(
            ["dpkg", "--compare-versions", left, "lt", right],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ConfigError("required tool not found: dpkg") from exc
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:
        return False
    detail = proc.stderr.strip() or f"exit status {proc.returncode}"
    raise ConfigError(f"dpkg cannot compare {left!r} and {right!r}: {detail}")


# --------------------------------------------------------------------------
# GitHub payload handling
# --------------------------------------------------------------------------


def valid_release_list(payload: Any, origin: str) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        raise InvalidResponse(f"{origin}: expected a JSON array of releases")
    releases: list[dict[str, Any]] = []
    for index, item in enumerate(payload):
        where = f"{origin}: release #{index}"
        if not isinstance(item, dict):
            raise InvalidResponse(f"{where} is not a JSON object")
        tag = item.get("tag_name")
        if not isinstance(tag, str) or not tag:
            raise InvalidResponse(f"{where} has no string tag_name")
        draft = item.get("draft")
        prerelease = item.get("prerelease")
        if not isinstance(draft, bool) or not isinstance(prerelease, bool):
            raise InvalidResponse(
                f"{where} has no boolean draft/prerelease field"
            )
        assets = item.get("assets", [])
        if not isinstance(assets, list):
            raise InvalidResponse(f"{where} has a non-array assets field")
        published = item.get("published_at")
        if published is not None and not isinstance(published, str):
            raise InvalidResponse(f"{where} has a non-string published_at")
        releases.append(
            {
                "tag": tag,
                "draft": draft,
                "prerelease": prerelease,
                "assets": assets,
                "released_at": published,
            }
        )
    return releases


def source_asset(release: dict[str, Any], version: str) -> dict[str, Any] | None:
    """Return the required unified source asset, if present and well formed."""
    wanted = ASSET_TEMPLATE.format(version=version)
    for asset in release["assets"]:
        if not isinstance(asset, dict) or asset.get("name") != wanted:
            continue
        url = asset.get("browser_download_url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise InvalidResponse(
                f"release {release['tag']}: {wanted} has no https download URL"
            )
        digest = asset.get("digest")
        if digest is not None and not isinstance(digest, str):
            raise InvalidResponse(
                f"release {release['tag']}: {wanted} has a non-string digest"
            )
        size = asset.get("size")
        return {
            "name": wanted,
            "url": url,
            "digest": digest,
            "size": size if isinstance(size, int) else None,
        }
    return None


# --------------------------------------------------------------------------
# network
# --------------------------------------------------------------------------


def fetch_json(url: str, timeout: float, retries: int) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        },
    )
    last_error = ""
    for attempt in range(retries + 1):
        try:
            opener = urllib.request.build_opener()
            with opener.open(request, timeout=timeout) as response:
                data = response.read(MAX_RESPONSE_BYTES + 1)
                charset = response.headers.get_content_charset() or "utf-8"
            if len(data) > MAX_RESPONSE_BYTES:
                raise InvalidResponse(
                    f"{url}: response exceeds {MAX_RESPONSE_BYTES} bytes"
                )
            try:
                text = data.decode(charset, errors="strict")
            except (LookupError, UnicodeDecodeError) as exc:
                raise InvalidResponse(f"{url}: cannot decode response: {exc}") from exc
            try:
                return json.loads(text)
            except json.JSONDecodeError as exc:
                raise InvalidResponse(
                    f"{url}: response is not valid JSON: {exc}"
                ) from exc
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code} from {url}"
            try:
                detail = exc.read(4096).decode("utf-8", errors="replace").strip()
            except (OSError, http.client.HTTPException):
                detail = ""
            if detail:
                last_error += f": {detail[:300]}"
            if exc.code in RETRYABLE_HTTP_STATUS and attempt < retries:
                time.sleep(0.3 * (attempt + 1))
                continue
            if exc.code == 403:
                last_error += " (possibly an unauthenticated rate limit)"
            raise NetworkError(last_error) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            last_error = f"cannot reach {url}: {reason}"
            if attempt < retries:
                time.sleep(0.3 * (attempt + 1))
                continue
            raise NetworkError(last_error) from exc
    raise NetworkError(last_error or f"cannot reach {url}")


def fetch_release_pages(api_url: str, timeout: float, retries: int) -> list[Any]:
    releases: list[Any] = []
    for page in range(1, MAX_PAGES + 1):
        separator = "&" if urllib.parse.urlsplit(api_url).query else "?"
        url = f"{api_url}{separator}per_page={PAGE_SIZE}&page={page}"
        payload = fetch_json(url, timeout, retries)
        if not isinstance(payload, list):
            raise InvalidResponse(
                f"{url}: expected a JSON array of releases, got "
                f"{type(payload).__name__}"
            )
        releases.extend(payload)
        if len(payload) < PAGE_SIZE:
            return releases
    print(
        f"warning: stopped after {MAX_PAGES} pages; older releases were not read",
        file=sys.stderr,
    )
    return releases


# --------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------


def load_saved_releases(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read --releases-json {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidResponse(f"{path}: not valid JSON: {exc}") from exc


def discover(
    releases: list[dict[str, Any]],
    current_version: str,
) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    """Pick the newest stable release that ships the unified source tarball.

    Returns (candidate, skipped).  skipped explains stable releases newer than
    the pin that could not be used, so a missing source asset is visible
    instead of silently looking like "no update".
    """
    eligible: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    for release in releases:
        if release["draft"] or release["prerelease"]:
            continue
        version = release_version(release["tag"])
        if version is None:
            skipped.append(
                {
                    "tag": release["tag"],
                    "version": "",
                    "reason": "unusable-version-tag",
                }
            )
            continue
        asset = source_asset(release, version)
        if asset is None:
            if version_lt(current_version, version):
                skipped.append(
                    {
                        "tag": release["tag"],
                        "version": version,
                        "reason": "missing-source-asset",
                    }
                )
            continue
        eligible.append(
            {
                "version": version,
                "tag": release["tag"],
                "asset_name": asset["name"],
                "asset_url": asset["url"],
                "digest": asset["digest"],
                "size": asset["size"],
                "released_at": release["released_at"],
            }
        )

    newest: dict[str, Any] | None = None
    for release in eligible:
        if newest is None or version_lt(newest["version"], release["version"]):
            newest = release

    if newest is None or not version_lt(current_version, newest["version"]):
        return None, skipped
    return newest, skipped


def run(args: argparse.Namespace) -> dict[str, Any]:
    env = read_env_file(Path(args.env))
    current_version = check_version(
        require(env, "UPSTREAM_VERSION"), "UPSTREAM_VERSION"
    )
    current_url = require(env, "UPSTREAM_URL")
    repository, current_tag, _current_asset = parse_release_url(current_url)

    if args.releases_json and args.api_url:
        raise ConfigError("--releases-json and --api-url cannot be used together")

    if args.releases_json:
        payload = load_saved_releases(Path(args.releases_json))
        origin = args.releases_json
        api_url = None
    else:
        api_url = args.api_url or (
            f"https://api.github.com/repos/{repository}/releases"
        )
        payload = fetch_release_pages(api_url, args.timeout, args.retries)
        origin = api_url

    releases = valid_release_list(payload, origin)
    candidate, skipped = discover(releases, current_version)

    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "update-available" if candidate else "up-to-date",
        "current": {
            "version": current_version,
            "tag": current_tag,
            "asset_url": current_url,
            "sha256": env.get("UPSTREAM_SHA256") or None,
        },
        "candidate": candidate,
        "skipped": skipped,
        "upstream": {
            "repository": repository,
            "release_api": api_url,
        },
        "verification": {
            "digest_source": "GitHub release asset metadata; may be null",
            "digest_is_not_verification": True,
            "required": (
                "After downloading candidate.asset_url, compute SHA-256 and "
                "compare it with the release's published checksum before "
                "updating upstream.env."
            ),
        },
    }
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check-upstream.py",
        description=(
            "Read-only check for a newer stable NekoBox unified source release. "
            "Never downloads or modifies files."
        ),
        epilog=(
            "Exit codes: 0 check completed (see status), 2 configuration error, "
            "3 network/HTTP error, 4 malformed API response. "
            "The candidate digest is optional metadata and may be null; verify "
            "the downloaded tarball's SHA-256 separately."
        ),
    )
    parser.add_argument(
        "--env",
        default=str(DEFAULT_ENV),
        help="upstream.env to read (default: %(default)s)",
    )
    parser.add_argument(
        "--releases-json",
        metavar="PATH",
        help="read a saved GitHub /releases JSON array instead of the network",
    )
    parser.add_argument(
        "--api-url",
        metavar="URL",
        help="override the GitHub releases API URL (mirrors/testing)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="network timeout per request (default: %(default)s)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        metavar="N",
        help="retries for transient network/5xx failures (default: %(default)s)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.retries < 0:
        parser.error("--retries cannot be negative")
    try:
        result = run(args)
    except CheckError as exc:
        json.dump(
            {
                "schema_version": SCHEMA_VERSION,
                "status": "error",
                "error": {"kind": exc.kind, "message": str(exc)},
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code

    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")

    for item in result["skipped"]:
        label = item["version"] or item["tag"]
        print(
            f"warning: stable release {label} skipped: "
            f"{item['reason'].replace('-', ' ')}",
            file=sys.stderr,
        )
    candidate = result["candidate"]
    if candidate is None:
        print(
            f"up to date: {result['current']['version']} is the newest usable "
            "stable release",
            file=sys.stderr,
        )
    else:
        print(
            f"update available: {result['current']['version']} -> "
            f"{candidate['version']} ({candidate['asset_name']})",
            file=sys.stderr,
        )
        if candidate["digest"] is None:
            print(
                "note: GitHub supplied no digest for this asset; verify the "
                "downloaded tarball's SHA-256 yourself",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
