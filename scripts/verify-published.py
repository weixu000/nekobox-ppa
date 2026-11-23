#!/usr/bin/env python3
"""Verify the NekoBox binary and source published in the Launchpad PPA.

The PPA's Packages and Sources indexes are the authority.  The supported
targets are defined here explicitly (noble, resolute, stonking); the verifier
does not read the legacy Launchpad git recipe.  For each target this script:

  * downloads dists/<series>/main/binary-amd64/Packages.gz;
  * finds the published version derived from the current upstream.env pin;
  * verifies the .deb against every strong digest the index supplies (SHA256
    and/or SHA512; stonking currently publishes SHA512 only);
  * verifies that the source package is a 3.0 (quilt) .dsc with an orig
    tarball and a debian tarball, using the Sources index checksums;
  * extracts the .deb and checks that the GUI, matching core and generated
    third-party notice index are present.

When a series has not published the version yet, the public Launchpad archive
API is consulted for the signed source upload and binary build records.  A
terminal failure (deleted source, failed to build/upload, chroot problem,
superseded build, cancelled build, or an unrecognised state) fails
immediately with the concrete record URL.  An ordinary queued, uploading or
pending source stays "pending" so a scheduled run can retry, but a pending
state that has not moved for --max-pending-hours (default 24) becomes a
"stale" failure.  A version with no recorded upload at all is also pending,
and becomes stale once the pin's commit is older than the same limit.  A
scheduled run treats ordinary pending as success; pass --require-published for
a manual verification that must fail.

Usage:
    scripts/verify-published.py
    scripts/verify-published.py --series noble,resolute --require-published
    scripts/verify-published.py --version 5.11.28.4 --json build/verified.json
    scripts/verify-published.py --expect-series noble,resolute,stonking

Exit codes: 0 verified or ordinary pending, 1 mismatch/failed/stale or pending
with --require-published, 2 usage/configuration, 3 network or Launchpad API.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 3
PPA_BASE = "https://ppa.launchpadcontent.net/oblivionw26/nekobox/ubuntu"
ARCH = "amd64"
CHUNK = 1024 * 1024
MAX_DOWNLOAD = 512 * 1024 * 1024
STRONG_DIGESTS = ("SHA256", "SHA512")

# The supported build targets, in publication order.  A new Launchpad target
# must be added here deliberately; nothing is discovered from the legacy git
# recipe.
KNOWN_SERIES: dict[str, dict[str, str]] = {
    "noble": {"base": "ubuntu:24.04", "suffix": "~ubuntu24.04.1"},
    "resolute": {"base": "ubuntu:26.04", "suffix": "~ubuntu26.04.1"},
    "stonking": {"base": "ubuntu:26.10", "suffix": "~ubuntu26.10.1"},
}
SERIES = tuple(KNOWN_SERIES)

ARCHIVE = "~oblivionw26/+archive/ubuntu/nekobox"
DEFAULT_MAX_PENDING_HOURS = 24.0

# PPA indexes are mutable and may be served through a cache. Retry transient
# GET failures and request fresh responses without changing archive URLs.
TRANSIENT_HTTP_STATUSES = frozenset({500, 502, 503, 504})
RETRY_DELAYS = (1.0, 2.0, 4.0)
FETCH_HEADERS = {
    "User-Agent": "nekobox-ppa-verify-published/3",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}

VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+~:-]{0,127}$")
FILENAME_RE = re.compile(r"^pool/[A-Za-z0-9.+~_/-]+\.deb$")
POOL_RE = re.compile(r"^pool/[A-Za-z0-9.+~_/-]+$")
DSC_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~_:-]*\.dsc$")
SOURCE_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~_:-]*$")

# Launchpad build states, from the public API documentation.
BUILD_FAILURES = frozenset(
    {
        "Failed to build",
        "Failed to upload",
        "Chroot problem",
        "Build for superseded Source",
        "Cancelled build",
    }
)
BUILD_PENDING = frozenset(
    {
        "Needs building",
        "Dependency wait",
        "Currently building",
        "Uploading build",
        "Cancelling build",
        "Gathering build output",
        "Successfully built",
    }
)
# An uploaded source first appears as Pending and later as Published.  Only an
# explicitly removed upload is a terminal source failure; a Superseded record
# may simply have been replaced by a newer upload of the same version.
SOURCE_ACTIVE = ("Published", "Pending")
SOURCE_FAILURE = ("Deleted", "Obsolete")

FILE_FIELDS = {
    "Files": "MD5",
    "Checksums-Sha1": "SHA1",
    "Checksums-Sha256": "SHA256",
    "Checksums-Sha512": "SHA512",
}
DIGEST_LENGTHS = {"MD5": 32, "SHA1": 40, "SHA256": 64, "SHA512": 128}


class VerifyError(Exception):
    exit_code = 1


class UsageError(VerifyError):
    exit_code = 2


class NetworkError(VerifyError):
    exit_code = 3


@dataclass(frozen=True)
class BuildEvidence:
    state: str
    created: datetime | None = None
    built: datetime | None = None
    url: str | None = None
    version: str | None = None
    series: str | None = None


@dataclass(frozen=True)
class SourceEvidence:
    version: str
    status: str
    created: datetime | None = None
    made_pending: datetime | None = None
    published: datetime | None = None
    url: str | None = None
    builds: tuple[BuildEvidence, ...] = ()


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc}") from exc
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def parse_packages(text: str) -> list[dict[str, str]]:
    """Parse Debian Packages/Sources stanzas into dictionaries.

    Continuation lines are appended to the previous field (last field wins).
    """
    stanzas: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if not line.strip():
            if current:
                stanzas.append(current)
                current = {}
                last_key = None
            continue
        if line.startswith(" ") and last_key:
            current[last_key] += "\n" + line.strip()
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        last_key = key.strip()
        current[last_key] = value.strip()
    if current:
        stanzas.append(current)
    return stanzas


def strip_clearsign(text: str) -> str:
    """Return the deb822 body of a clearsigned .dsc, if it is signed."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        return text
    start = 1
    for index in range(1, len(lines)):
        if not lines[index].strip():
            start = index + 1
            break
    end = len(lines)
    for index in range(start, len(lines)):
        if lines[index].startswith("-----BEGIN PGP SIGNATURE-----"):
            end = index
            break
    return "\n".join(lines[start:end])


def version_matches(published: str, base_version: str) -> bool:
    return published == base_version or published.startswith(base_version + "~")


def select_package(
    stanzas: list[dict[str, str]], base_version: str, package: str = "nekobox"
) -> dict[str, str] | None:
    matches = [
        stanza
        for stanza in stanzas
        if stanza.get("Package") == package
        and version_matches(stanza.get("Version", ""), base_version)
    ]
    if not matches:
        return None
    # There should be one candidate per series; if several exist, prefer the
    # one dpkg considers newest rather than relying on index order.
    best = matches[0]
    for candidate in matches[1:]:
        proc = subprocess.run(
            ["dpkg", "--compare-versions", best["Version"], "lt",
             candidate["Version"]],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if proc.returncode == 0:
            best = candidate
    return best


def parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def series_from_link(link: Any) -> str | None:
    if not isinstance(link, str) or not link:
        return None
    name = link.rstrip("/").rsplit("/", 1)[-1]
    return name or None


def build_kind(state: str) -> str:
    if state in BUILD_FAILURES:
        return "failure"
    if state in BUILD_PENDING:
        return "pending"
    return "unknown"


def normalize_build(build: Any, series: str | None = None) -> BuildEvidence:
    return BuildEvidence(
        state=str(getattr(build, "buildstate", "") or ""),
        created=parse_timestamp(getattr(build, "datecreated", None)),
        built=parse_timestamp(getattr(build, "datebuilt", None)),
        url=getattr(build, "web_link", None) or getattr(build, "self_link", None),
        version=getattr(build, "source_package_version", None),
        series=series or series_from_link(getattr(build, "distro_series_link", None)),
    )


def normalize_source(source: Any) -> SourceEvidence:
    builds = tuple(normalize_build(build) for build in source.getBuilds())
    return SourceEvidence(
        version=str(getattr(source, "source_package_version", "") or ""),
        status=str(getattr(source, "status", "") or ""),
        created=parse_timestamp(getattr(source, "date_created", None)),
        made_pending=parse_timestamp(getattr(source, "date_made_pending", None)),
        published=parse_timestamp(getattr(source, "date_published", None)),
        url=getattr(source, "web_link", None) or getattr(source, "self_link", None),
        builds=builds,
    )


def _latest_time(*values: datetime | None) -> datetime | None:
    present = [value for value in values if value is not None]
    return max(present) if present else None


def _newest_source(sources: Iterable[Any]) -> Any:
    """Return the most recent of several matching source publications."""

    def timestamp(source: Any) -> datetime:
        return _latest_time(
            parse_timestamp(getattr(source, "date_published", None)),
            parse_timestamp(getattr(source, "date_created", None)),
            parse_timestamp(getattr(source, "date_made_pending", None)),
        ) or datetime.min.replace(tzinfo=timezone.utc)

    return max(sources, key=timestamp)


def _decision(status: str, detail: str, evidence: dict[str, Any]) -> dict[str, Any]:
    entry = dict(evidence)
    entry["status"] = status
    entry["detail"] = detail
    return entry


def _pending_or_stale(
    detail: str,
    activity: datetime | None,
    now: datetime,
    max_pending_hours: float,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    entry = _decision("pending", detail, evidence)
    entry["last_activity"] = iso_timestamp(activity)
    entry["stale_after_hours"] = max_pending_hours
    if max_pending_hours > 0 and activity is not None:
        age = now - activity
        if age > timedelta(hours=max_pending_hours):
            entry["status"] = "stale"
            entry["detail"] = (
                f"{detail}; no Launchpad activity since {iso_timestamp(activity)} "
                f"({age.total_seconds() / 3600:.1f}h > {max_pending_hours:g}h)"
            )
    return entry


def classify_publication(
    *,
    series: str,
    base_version: str,
    source: SourceEvidence | None,
    builds: Iterable[BuildEvidence],
    now: datetime,
    max_pending_hours: float,
    pin_committed: datetime | None = None,
) -> dict[str, Any]:
    """Classify a not-yet-published version using public Launchpad evidence.

    Returns a result entry with status "pending", "stale" or "failed".  The
    caller decides whether pending is acceptable; failed and stale are always
    failures.
    """
    relevant = list(builds)
    if source:
        relevant.extend(source.builds)
    unique: dict[tuple[Any, ...], BuildEvidence] = {}
    for build in relevant:
        key = (build.url, build.state, build.created, build.version)
        unique[key] = build
    relevant = list(unique.values())
    latest = max(
        relevant,
        key=lambda build: build.created
        or datetime.min.replace(tzinfo=timezone.utc),
        default=None,
    )

    evidence: dict[str, Any] = {
        "series": series,
        "source_url": source.url if source else None,
        "source_status": source.status if source else None,
        "source_created": iso_timestamp(source.created) if source else None,
        "source_published": iso_timestamp(source.published) if source else None,
        "build_url": latest.url if latest else None,
        "build_state": latest.state if latest else None,
        "build_created": iso_timestamp(latest.created) if latest else None,
        "build_built": iso_timestamp(latest.built) if latest else None,
    }

    if source and source.status not in SOURCE_ACTIVE:
        return _decision(
            "failed",
            f"Launchpad source publication is {source.status}",
            evidence,
        )

    if latest is not None:
        kind = build_kind(latest.state)
        if kind == "unknown":
            return _decision(
                "failed",
                f"unrecognised Launchpad build state {latest.state!r}",
                evidence,
            )
        if kind == "failure":
            return _decision(
                "failed",
                f"Launchpad build {latest.state}",
                evidence,
            )
        activity = _latest_time(
            latest.created,
            latest.built,
            source.created if source else None,
            source.made_pending if source else None,
            source.published if source else None,
        )
        if source and source.status == "Published":
            detail = (
                "source is published but the Packages index does not list it yet"
            )
        elif source is not None:
            detail = f"source was accepted; latest build is {latest.state}"
        elif latest.state == "Successfully built":
            detail = "build succeeded; waiting for upload/publication"
        else:
            detail = f"build is {latest.state}"
        return _pending_or_stale(
            detail, activity, now, max_pending_hours, evidence
        )

    if source is not None:
        activity = _latest_time(
            source.made_pending, source.created, source.published
        )
        if source.status == "Published":
            detail = (
                "source is published but the Packages index does not list it yet"
            )
        else:
            detail = "source was accepted; no build record yet"
        return _pending_or_stale(
            detail, activity, now, max_pending_hours, evidence
        )

    if (
        pin_committed is not None
        and max_pending_hours > 0
        and now - pin_committed > timedelta(hours=max_pending_hours)
    ):
        age = now - pin_committed
        return _decision(
            "stale",
            f"no Launchpad source upload for {base_version} was recorded "
            f"within {max_pending_hours:g}h of the pin "
            f"({age.total_seconds() / 3600:.1f}h > {max_pending_hours:g}h)",
            evidence,
        )
    return _decision(
        "pending",
        f"no Launchpad source upload for {base_version} is recorded yet",
        evidence,
    )


class _TransientFetchError(Exception):
    """A GET that may succeed if retried."""


def _download_once(
    request: urllib.request.Request,
    url: str,
    destination: Path,
    timeout: float,
) -> bool:
    """Attempt one idempotent GET; raise _TransientFetchError to retry."""
    tmp = destination.with_name(destination.name + ".part")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            length = response.headers.get("Content-Length")
            try:
                length_value = int(length) if length is not None else None
            except ValueError:
                length_value = None
            if length_value is not None and length_value > MAX_DOWNLOAD:
                raise VerifyError(f"{url}: file is larger than {MAX_DOWNLOAD} bytes")
            total = 0
            with tmp.open("wb") as handle:
                while True:
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOWNLOAD:
                        raise VerifyError(f"{url}: download exceeded size limit")
                    handle.write(chunk)
        os.replace(tmp, destination)
        return True
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 404:
            return False
        if exc.code not in TRANSIENT_HTTP_STATUSES:
            raise NetworkError(f"HTTP {exc.code} fetching {url}") from exc
        raise _TransientFetchError(f"HTTP {exc.code}") from exc
    except (
        urllib.error.URLError,
        http.client.HTTPException,
        TimeoutError,
        OSError,
    ) as exc:
        reason = getattr(exc, "reason", exc)
        raise _TransientFetchError(str(reason)) from exc
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def fetch(url: str, destination: Path, timeout: float) -> bool:
    """Download an idempotent URL, retrying transient server/network errors.

    A 404 still means "not published yet" and is returned as False without a
    retry.  Non-transient HTTP errors fail immediately.  Checksum validation
    happens after this function returns and is not retried here.
    """
    request = urllib.request.Request(url, headers=FETCH_HEADERS)
    attempts = len(RETRY_DELAYS) + 1
    last_reason = ""
    for attempt in range(attempts):
        try:
            return _download_once(request, url, destination, timeout)
        except _TransientFetchError as exc:
            last_reason = str(exc)
            if attempt + 1 >= attempts:
                break
            time.sleep(RETRY_DELAYS[attempt])
    raise NetworkError(
        f"cannot fetch {url} after {attempts} attempts: {last_reason}"
    )


def digests_for(package: dict[str, str]) -> dict[str, str]:
    digests = {
        key: package[key].lower()
        for key in STRONG_DIGESTS
        if package.get(key)
    }
    if not digests:
        raise VerifyError(
            f"{package.get('Version')}: index supplies no SHA256 or SHA512 digest"
        )
    for key, value in digests.items():
        length = 64 if key == "SHA256" else 128
        if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
            raise VerifyError(f"{package.get('Version')}: malformed {key} digest")
    return digests


def hash_file(path: Path) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            sha256.update(chunk)
            sha512.update(chunk)
    return sha256.hexdigest(), sha512.hexdigest()


def verify_hashes(path: Path, expected: dict[str, str]) -> tuple[str, str]:
    sha256, sha512 = hash_file(path)
    actual = {"SHA256": sha256, "SHA512": sha512}
    for name, value in expected.items():
        if not hmac.compare_digest(actual[name], value):
            raise VerifyError(
                f"{path.name}: {name} mismatch (index {value}, file {actual[name]})"
            )
    return sha256, sha512


def inspect_package(deb: Path, expected_version: str, expected_index: Path) -> dict[str, Any]:
    try:
        version = subprocess.check_output(
            ["dpkg-deb", "-f", str(deb), "Version"], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise VerifyError(f"cannot read package metadata from {deb}: {exc}") from exc
    if version != expected_version:
        raise VerifyError(f"{deb.name}: version is {version}, expected {expected_version}")

    with tempfile.TemporaryDirectory(prefix="nekobox-published-") as tmp:
        root = Path(tmp)
        try:
            subprocess.run(
                ["dpkg-deb", "-x", str(deb), str(root)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise VerifyError(f"{deb.name}: cannot extract the package: {exc}") from exc
        for rel in (
            "usr/bin/nekobox",
            "usr/libexec/Iblis/nekobox",
            "usr/libexec/Iblis/nekobox_core",
        ):
            path = root / rel
            if not path.exists():
                raise VerifyError(f"{deb.name}: missing {rel}")
            if not os.access(path, os.X_OK):
                raise VerifyError(f"{deb.name}: {rel} is not executable")
        if (root / "usr/bin/sing-box").exists():
            raise VerifyError(f"{deb.name}: still ships /usr/bin/sing-box")
        installed_index = root / "usr/share/doc/nekobox/third-party/INDEX.txt"
        if not installed_index.is_file():
            installed_index = root / "usr/share/doc/nekobox/third-party/INDEX.txt.gz"
        if not installed_index.is_file():
            raise VerifyError(f"{deb.name}: missing the third-party INDEX")
        index_bytes = installed_index.read_bytes()
        if installed_index.suffix == ".gz":
            index_bytes = gzip.decompress(index_bytes)
        if expected_index.is_file():
            if index_bytes != expected_index.read_bytes():
                raise VerifyError(
                    f"{deb.name}: third-party INDEX differs from the repository copy"
                )
            index_sha256 = hashlib.sha256(index_bytes).hexdigest()
        else:
            index_sha256 = hashlib.sha256(index_bytes).hexdigest()
    return {"version": version, "index_sha256": index_sha256}


def merge_file_entries(stanza: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Merge Files/Checksums-* into {name: {size, hashes}}.

    Debian source indexes split one file list across several checksum fields;
    every field for a name must agree on the size.
    """
    merged: dict[str, dict[str, Any]] = {}
    for field_name, algorithm in FILE_FIELDS.items():
        raw = stanza.get(field_name)
        if not raw:
            continue
        for line in raw.splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) != 3:
                raise VerifyError(
                    f"{field_name} has a malformed entry: {line.strip()!r}"
                )
            digest, size_text, name = parts
            if not SOURCE_FILE_RE.fullmatch(name):
                raise VerifyError(f"unsafe source file name {name!r}")
            if not size_text.isdigit():
                raise VerifyError(f"{name}: invalid size {size_text!r}")
            expected_length = DIGEST_LENGTHS[algorithm]
            if not re.fullmatch(
                rf"[0-9a-fA-F]{{{expected_length}}}", digest
            ):
                raise VerifyError(f"{name}: malformed {algorithm} digest")
            size = int(size_text)
            entry = merged.setdefault(name, {"size": size, "hashes": {}})
            if entry["size"] != size:
                raise VerifyError(
                    f"{name}: inconsistent size in the source index"
                )
            entry["hashes"][algorithm] = digest.lower()
    return merged


def source_metadata(
    stanza: dict[str, str],
    dsc_text: str,
    dsc_name: str,
    base_version: str,
) -> dict[str, Any]:
    """Validate the quilt .dsc against its Sources stanza.

    The orig and debian tarballs are not downloaded: the .dsc must reference
    exactly one of each, and the referenced names, sizes and SHA256 must match
    the Sources index that apt uses.
    """
    source = stanza.get("Package") or stanza.get("Source")
    version = stanza.get("Version")
    if not source or not version:
        raise VerifyError("source index stanza lacks Package/Version")
    if dsc_name != f"{source}_{version}.dsc":
        raise VerifyError(
            f"{dsc_name}: expected the .dsc name {source}_{version}.dsc"
        )
    index_format = stanza.get("Format", "")
    if index_format != "3.0 (quilt)":
        raise VerifyError(
            f"{source}: source index format is {index_format!r}, "
            "expected 3.0 (quilt)"
        )

    dsc_stanzas = parse_packages(strip_clearsign(dsc_text))
    if len(dsc_stanzas) != 1:
        raise VerifyError(f"{dsc_name}: cannot parse exactly one .dsc stanza")
    dsc = dsc_stanzas[0]
    if dsc.get("Format") != "3.0 (quilt)":
        raise VerifyError(
            f"{dsc_name}: format is {dsc.get('Format')!r}, expected 3.0 (quilt)"
        )
    if dsc.get("Source") != source:
        raise VerifyError(
            f"{dsc_name}: Source is {dsc.get('Source')!r}, expected {source}"
        )
    if dsc.get("Version") != version:
        raise VerifyError(
            f"{dsc_name}: Version is {dsc.get('Version')!r}, expected {version}"
        )

    index_files = merge_file_entries(stanza)
    dsc_files = merge_file_entries(dsc)
    orig = [name for name in dsc_files if ".orig.tar." in name]
    debian = [name for name in dsc_files if ".debian.tar." in name]
    if len(orig) != 1:
        raise VerifyError(
            f"{dsc_name}: expected exactly one orig tarball, found {len(orig)}"
        )
    if len(debian) != 1:
        raise VerifyError(
            f"{dsc_name}: expected exactly one debian tarball, found {len(debian)}"
        )
    upstream = (
        base_version.rsplit("-", 1)[0] if "-" in base_version else base_version
    )
    if not orig[0].startswith(f"{source}_{upstream}.orig.tar."):
        raise VerifyError(
            f"{dsc_name}: orig tarball {orig[0]!r} does not match "
            f"upstream {upstream}"
        )
    if not debian[0].startswith(f"{source}_{version}.debian.tar."):
        raise VerifyError(
            f"{dsc_name}: debian tarball {debian[0]!r} does not match "
            f"version {version}"
        )
    for name in (orig[0], debian[0]):
        if name not in index_files:
            raise VerifyError(
                f"{dsc_name}: references {name}, which the Sources index "
                "does not list"
            )
        if index_files[name]["size"] != dsc_files[name]["size"]:
            raise VerifyError(
                f"{dsc_name}: {name} size differs between the .dsc and Sources"
            )
        if "SHA256" not in dsc_files[name]["hashes"]:
            raise VerifyError(f"{dsc_name}: {name} has no SHA256 in the .dsc")
        for algorithm in ("SHA1", "SHA256", "SHA512"):
            dsc_digest = dsc_files[name]["hashes"].get(algorithm)
            index_digest = index_files[name]["hashes"].get(algorithm)
            if dsc_digest and index_digest and dsc_digest != index_digest:
                raise VerifyError(
                    f"{dsc_name}: {name} {algorithm} differs between the "
                    ".dsc and Sources"
                )
    return {
        "format": "3.0 (quilt)",
        "dsc": dsc_name,
        "orig": orig[0],
        "debian": debian[0],
        "orig_size": dsc_files[orig[0]]["size"],
        "debian_size": dsc_files[debian[0]]["size"],
    }


def verify_source(
    series: str,
    published_version: str,
    base_version: str,
    cache_dir: Path,
    timeout: float,
) -> dict[str, Any]:
    index_url = f"{PPA_BASE}/dists/{series}/main/source/Sources.gz"
    sources_path = cache_dir / f"Sources-{series}.gz"
    if not fetch(index_url, sources_path, timeout):
        raise VerifyError(f"{series}: Sources index is not published")
    try:
        text = gzip.decompress(sources_path.read_bytes()).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise VerifyError(f"{series}: cannot read Sources index: {exc}") from exc
    stanza = next(
        (
            item
            for item in parse_packages(text)
            if item.get("Package") == "nekobox"
            and item.get("Version") == published_version
        ),
        None,
    )
    if stanza is None:
        raise VerifyError(
            f"{series}: source package {published_version} is not in Sources"
        )

    directory = stanza.get("Directory", "")
    if not POOL_RE.fullmatch(directory) or ".." in Path(directory).parts:
        raise VerifyError(f"{series}: unsafe source Directory {directory!r}")
    index_files = merge_file_entries(stanza)
    dsc_entries = [
        (name, entry)
        for name, entry in index_files.items()
        if name.endswith(".dsc")
    ]
    if len(dsc_entries) != 1:
        raise VerifyError(
            f"{series}: expected one .dsc in Sources, found {len(dsc_entries)}"
        )
    dsc_name, dsc_entry = dsc_entries[0]
    if not DSC_NAME_RE.fullmatch(dsc_name):
        raise VerifyError(f"{series}: unsafe .dsc name {dsc_name!r}")
    expected = {
        algorithm: dsc_entry["hashes"][algorithm]
        for algorithm in STRONG_DIGESTS
        if algorithm in dsc_entry["hashes"]
    }
    if not expected:
        raise VerifyError(
            f"{series}: {dsc_name}: no SHA256 or SHA512 digest in Sources"
        )

    dsc_url = f"{PPA_BASE}/{directory}/{dsc_name}"
    dsc_path = cache_dir / dsc_name
    sha256 = ""
    if dsc_path.is_file():
        try:
            sha256, sha512 = verify_hashes(dsc_path, expected)
        except VerifyError:
            dsc_path.unlink()
            sha256 = ""
    if not sha256:
        if not fetch(dsc_url, dsc_path, timeout):
            raise NetworkError(f"{series}: published source {dsc_name} is missing")
        if dsc_path.stat().st_size != dsc_entry["size"]:
            raise VerifyError(
                f"{series}: {dsc_name} size mismatch "
                f"({dsc_path.stat().st_size} != {dsc_entry['size']})"
            )
        sha256, sha512 = verify_hashes(dsc_path, expected)

    try:
        dsc_text = dsc_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise VerifyError(f"{series}: cannot read {dsc_name}: {exc}") from exc
    metadata = source_metadata(stanza, dsc_text, dsc_name, base_version)
    metadata.update(
        {
            "status": "verified",
            "directory": directory,
            "dsc_url": dsc_url,
            "dsc_sha256": sha256,
            "dsc_sha512": sha512,
        }
    )
    return metadata


def verify_package(
    series: str,
    base_version: str,
    repo: Path,
    cache_dir: Path,
    timeout: float,
) -> tuple[dict[str, Any] | None, str]:
    """Verify the binary package in Packages, or return (None, reason)."""
    index_url = f"{PPA_BASE}/dists/{series}/main/binary-{ARCH}/Packages.gz"
    packages_path = cache_dir / f"Packages-{series}.gz"
    if not fetch(index_url, packages_path, timeout):
        return None, "Packages index is not published"
    try:
        text = gzip.decompress(packages_path.read_bytes()).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise VerifyError(f"{series}: cannot read Packages index: {exc}") from exc
    package = select_package(parse_packages(text), base_version)
    if package is None:
        return None, "version is not in Packages yet"

    filename = package.get("Filename", "")
    if not FILENAME_RE.fullmatch(filename):
        raise VerifyError(f"{series}: unsafe or missing Filename {filename!r}")
    if ".." in Path(filename).parts:
        raise VerifyError(f"{series}: Filename contains '..': {filename!r}")
    expected = digests_for(package)
    size = int(package["Size"]) if package.get("Size", "").isdigit() else None
    deb_path = cache_dir / Path(filename).name
    if deb_path.is_file():
        try:
            sha256, sha512 = verify_hashes(deb_path, expected)
        except VerifyError:
            deb_path.unlink()
            sha256 = sha512 = ""
    else:
        sha256 = sha512 = ""
    deb_url = f"{PPA_BASE}/{filename}"
    if not sha256:
        if not fetch(deb_url, deb_path, timeout):
            raise NetworkError(f"{series}: published package {filename} is missing")
        if size is not None and deb_path.stat().st_size != size:
            raise VerifyError(
                f"{series}: size mismatch ({deb_path.stat().st_size} != {size})"
            )
        sha256, sha512 = verify_hashes(deb_path, expected)

    inspected = inspect_package(
        deb_path,
        package["Version"],
        repo / "debian" / "third-party" / "INDEX.txt",
    )
    return {
        "status": "verified",
        "published_version": package["Version"],
        "filename": filename,
        "size": deb_path.stat().st_size,
        "sha256": sha256,
        "sha512": sha512,
        "digests_verified": sorted(expected),
        "deb_url": deb_url,
        "base_image": KNOWN_SERIES[series]["base"],
        **inspected,
    }, ""


def login_launchpad(timeout: float):
    try:
        from launchpadlib.launchpad import Launchpad
    except ImportError as exc:
        raise UsageError(
            "launchpadlib is required for archive-state checks "
            "(install python3-launchpadlib)"
        ) from exc
    socket.setdefaulttimeout(timeout)
    try:
        return Launchpad.login_anonymously(
            "nekobox-ppa-verify-published", "production", version="devel"
        )
    except Exception as exc:  # noqa: BLE001 - report API failure, no secrets
        raise NetworkError(
            f"cannot log in to the Launchpad API: {type(exc).__name__}: {exc}"
        ) from exc


class LaunchpadContext:
    """Read-only view of the public PPA archive."""

    def __init__(self, launchpad: Any, timeout: float) -> None:
        self.launchpad = launchpad
        self.timeout = timeout
        self.archive = self._wrap(lambda: launchpad.load(ARCHIVE))
        records = self._wrap(
            lambda: list(
                self.archive.getBuildRecords(source_name="nekobox")
            )
        )
        self.archive_builds = tuple(
            normalize_build(build) for build in records
        )

    def _wrap(self, action):
        try:
            return action()
        except Exception as exc:  # noqa: BLE001 - no credentials are involved
            raise NetworkError(
                f"Launchpad API failure: {type(exc).__name__}: {exc}"
            ) from exc

    def _api(self, call, *args, **kwargs):
        return self._wrap(lambda: call(*args, **kwargs))

    def discover_series(self) -> list[str]:
        """Return the explicitly supported targets, in publication order."""
        return list(SERIES)

    def _sources_for_status(self, series_object: Any, status: str) -> list[Any]:
        return self._wrap(
            lambda: list(
                self.archive.getPublishedSources(
                    source_name="nekobox",
                    distro_series=series_object,
                    exact_match=True,
                    status=status,
                )
            )
        )

    def source_for(
        self, series: str, base_version: str
    ) -> SourceEvidence | None:
        series_object = self._api(self.launchpad.load, f"ubuntu/{series}")
        for status in (*SOURCE_ACTIVE, *SOURCE_FAILURE):
            matching = [
                source
                for source in self._sources_for_status(series_object, status)
                if version_matches(
                    getattr(source, "source_package_version", ""), base_version
                )
            ]
            if matching:
                chosen = _newest_source(matching)
                return self._wrap(lambda: normalize_source(chosen))
        return None

    def builds_for(
        self, series: str, base_version: str
    ) -> list[BuildEvidence]:
        return [
            build
            for build in self.archive_builds
            if build.series == series
            and build.version
            and version_matches(build.version, base_version)
        ]


def collect_launchpad_context(timeout: float) -> LaunchpadContext:
    return LaunchpadContext(login_launchpad(timeout), timeout)


def verify_series(
    series: str,
    base_version: str,
    repo: Path,
    cache_dir: Path,
    timeout: float,
    launchpad: LaunchpadContext,
    now: datetime,
    max_pending_hours: float,
    pin_committed: datetime | None,
) -> dict[str, Any]:
    entry, packages_detail = verify_package(
        series, base_version, repo, cache_dir, timeout
    )
    if entry is not None:
        try:
            entry["source"] = verify_source(
                series,
                entry["published_version"],
                base_version,
                cache_dir,
                timeout,
            )
        except NetworkError:
            raise
        except VerifyError as exc:
            return {
                "status": "failed",
                "detail": f"source verification failed: {exc}",
                "published_version": entry["published_version"],
                "deb_url": entry["deb_url"],
                "base_image": entry["base_image"],
            }
        return entry

    decision = classify_publication(
        series=series,
        base_version=base_version,
        source=launchpad.source_for(series, base_version),
        builds=launchpad.builds_for(series, base_version),
        now=now,
        max_pending_hours=max_pending_hours,
        pin_committed=pin_committed,
    )
    decision["base_image"] = KNOWN_SERIES[series]["base"]
    decision["packages_detail"] = packages_detail
    return decision


def git_commit_time(repo: Path, path: str = "upstream.env") -> datetime | None:
    try:
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "log",
                "-1",
                "--format=%ct",
                "--",
                path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return None
    output = proc.stdout.strip()
    if proc.returncode != 0 or not output.isdigit():
        return None
    return datetime.fromtimestamp(int(output), tz=timezone.utc)


def render_summary(result: dict[str, Any]) -> str:
    lines = [
        f"## Published PPA verification: {result['base_version']}",
        "",
        f"- PPA: {result.get('ppa') or '-'}",
        f"- targets: {', '.join(result.get('enabled_series', [])) or '-'}",
        "",
        "| Series | Status | Published version / detail | SHA256 |",
        "| --- | --- | --- | --- |",
    ]
    for series in result["series"]:
        entry = result["results"][series]
        status = entry["status"]
        if status == "verified":
            detail = entry["published_version"]
            source_format = (entry.get("source") or {}).get("format")
            if source_format:
                detail += f" ({source_format})"
            sha256 = f"`{entry['sha256']}`"
        else:
            detail = entry.get("detail", "").replace("|", "\\|")
            evidence_url = entry.get("build_url") or entry.get("source_url")
            if evidence_url:
                detail += f" ([evidence]({evidence_url}))"
            sha256 = "-"
        lines.append(f"| {series} | {status} | {detail} | {sha256} |")
    lines.append("")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(args.repo_root).resolve()
    env = read_env(repo / "upstream.env")
    version = args.version or env.get("UPSTREAM_VERSION", "")
    revision = env.get("DEBIAN_REVISION", "")
    base_version = args.base_version or (
        f"{version}-{revision}" if version and revision else ""
    )
    if not VERSION_RE.fullmatch(base_version):
        raise UsageError(f"not a usable base version: {base_version!r}")
    if args.max_pending_hours < 0:
        raise UsageError("--max-pending-hours must not be negative")
    if args.timeout <= 0:
        raise UsageError("--timeout must be greater than zero")

    now = datetime.now(timezone.utc)
    env_base_version = (
        f"{env.get('UPSTREAM_VERSION', '')}-{revision}"
        if env.get("UPSTREAM_VERSION") and revision
        else ""
    )
    # The pin's commit age only describes this version.  An explicitly
    # requested different version must not inherit it.
    pin_committed = (
        git_commit_time(repo)
        if base_version == env_base_version and args.max_pending_hours > 0
        else None
    )

    launchpad = collect_launchpad_context(args.timeout)
    enabled = launchpad.discover_series()

    expected: list[str] = []
    if args.expect_series:
        expected = [
            item.strip()
            for item in args.expect_series.split(",")
            if item.strip()
        ]
        unknown_expected = [
            item for item in expected if item not in KNOWN_SERIES
        ]
        if unknown_expected:
            raise UsageError(
                "unknown --expect-series: " + ", ".join(unknown_expected)
            )
        if set(enabled) != set(expected):
            raise UsageError(
                "supported target set does not match --expect-series: "
                f"targets={', '.join(enabled)}; "
                f"expected={', '.join(expected)}"
            )

    if args.series.strip() == "auto":
        selected = enabled
    else:
        selected = [
            item.strip()
            for item in args.series.split(",")
            if item.strip()
        ]
        if not selected:
            raise UsageError("--series selected no series")
        unknown = [item for item in selected if item not in KNOWN_SERIES]
        if unknown:
            raise UsageError(f"unknown series: {', '.join(unknown)}")
        # A supported target that is not selected is an explicit local filter.
    if not selected:
        raise UsageError("no series selected")

    cache_dir = Path(
        args.cache_dir or (repo / "build" / "published-cache")
    ).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, Any] = {}
    for series in selected:
        try:
            entry = verify_series(
                series,
                base_version,
                repo,
                cache_dir,
                args.timeout,
                launchpad,
                now,
                args.max_pending_hours,
                pin_committed,
            )
        except UsageError:
            raise
        except NetworkError:
            raise
        except VerifyError as exc:
            entry = {
                "status": "failed",
                "detail": str(exc),
                "base_image": KNOWN_SERIES[series]["base"],
            }
        entry.setdefault("base_image", KNOWN_SERIES[series]["base"])
        results[series] = entry

    failed = any(
        entry["status"] in ("failed", "stale")
        for entry in results.values()
    )
    pending = any(entry["status"] == "pending" for entry in results.values())
    result = {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "base_version": base_version,
        "ppa": PPA_BASE,
        "required_published": bool(args.require_published),
        "max_pending_hours": args.max_pending_hours,
        "ok": not failed and not (pending and args.require_published),
        "series": selected,
        # enabled_series is kept for workflow compatibility; it is now the
        # explicit supported target set, not a Launchpad recipe setting.
        "enabled_series": enabled,
        "targets": enabled,
        "results": results,
    }
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
    if args.summary:
        Path(args.summary).parent.mkdir(parents=True, exist_ok=True)
        Path(args.summary).write_text(render_summary(result), encoding="utf-8")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify-published.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parent.parent),
    )
    parser.add_argument("--version", help="upstream version (default: upstream.env)")
    parser.add_argument("--base-version", help="Debian base version to find")
    parser.add_argument(
        "--series",
        default="auto",
        help="'auto' verifies every explicitly supported target",
    )
    parser.add_argument(
        "--expect-series",
        help="require the supported target set to equal this comma-separated set",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="default: <repo-root>/build/published-cache",
    )
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument(
        "--max-pending-hours",
        type=float,
        default=DEFAULT_MAX_PENDING_HOURS,
        help="fail a pending Launchpad state older than this (0 disables)",
    )
    parser.add_argument("--require-published", action="store_true")
    parser.add_argument("--json", help="write the result as JSON")
    parser.add_argument("--summary", help="write a Markdown summary")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cache_dir is None:
        args.cache_dir = str(
            Path(args.repo_root).resolve() / "build" / "published-cache"
        )
    try:
        result = run(args)
    except VerifyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    for series in result["series"]:
        entry = result["results"][series]
        if entry["status"] == "verified":
            source_format = (entry.get("source") or {}).get("format")
            print(
                f"{series}: verified {entry['published_version']} "
                f"sha256={entry['sha256']}"
                + (f" source={source_format}" if source_format else "")
            )
        elif entry["status"] in ("failed", "stale"):
            build_url = entry.get("build_url")
            print(
                f"{series}: {entry['status']}: {entry.get('detail', '')}"
                + (f" (build: {build_url})" if build_url else "")
            )
        else:
            print(f"{series}: pending: {entry.get('detail', '')}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
