#!/usr/bin/env python3
"""Prepare, sign and upload NekoBox source packages to the Launchpad PPA.

The PPA receives normal signed Debian source uploads:

  1. ``plan`` checks the PPA for each series and decides which per-series
     versions still need an upload.  If the upstream version already exists,
     the archived orig tarball is located through the published .dsc and its
     SHA-256 is compared with the Sources index.  Launchpad keeps the orig
     bytes for an upstream version immutable, so a later packaging revision
     must reuse those exact bytes instead of repacking the upstream download.
  2. ``prepare`` builds the per-series source tree from either the archived
     orig or the pinned upstream tarball and rewrites only the first
     debian/changelog entry (version suffix and distribution).  The existing
     scripts/prepare-source.sh owns download, hashing, unpacking and the
     dpkg-source roundtrip.
  3. ``sign`` runs ``dpkg-buildpackage -S -sa`` and verifies the .changes, the
     .dsc, every checksum, the signatures and a dpkg-source extraction of the
     source package.  ``sign --unsigned`` performs the same build and
     roundtrip without a key, so CI can validate the exact prepared tree
     before the signing job.  No binary is built.
  4. ``upload`` refuses to run when the signing key is not registered on the
     Launchpad account, skips versions already pending/published, then runs
     dput.  dput success is a transfer result only; archive acceptance is
     asynchronous and is reported as ``pending`` until the public API shows
     the source.

Commands:
    scripts/source-upload.py plan --json build/upload-plan.json
    scripts/source-upload.py prepare --plan build/upload-plan.json --series noble
    scripts/source-upload.py sign --unsigned --plan build/upload-plan.json --series noble
    scripts/source-upload.py sign --plan build/upload-plan.json --series noble
    scripts/source-upload.py preflight --fingerprint FINGERPRINT
    scripts/source-upload.py upload --plan build/upload-plan.json --series noble

Environment used by ``sign`` (never printed):
    GNUPGHOME                 isolated keyring created by the workflow
    LP_GPG_PASSPHRASE_FILE    optional file with the key passphrase
    LP_GPG_KEY_ID             optional expected signing fingerprint

Exit codes: 0 success, 1 verification/upload failure, 2 usage, 3 network.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1
PPA_OWNER = "oblivionw26"
PPA_NAME = "nekobox"
PPA_BASE = f"https://ppa.launchpadcontent.net/{PPA_OWNER}/{PPA_NAME}/ubuntu"
PPA_ARCHIVE = f"~{PPA_OWNER}/+archive/ubuntu/{PPA_NAME}"
API_BASE = "https://api.launchpad.net/devel"
DPUT_TARGET = f"ppa:{PPA_OWNER}/{PPA_NAME}"

# Deliberately explicit: a new series needs a base image and the version suffix
# used for that series.
SERIES: dict[str, dict[str, str]] = {
    "noble": {"base": "ubuntu:24.04", "suffix": "~ubuntu24.04.1"},
    "resolute": {"base": "ubuntu:26.04", "suffix": "~ubuntu26.04.1"},
    "stonking": {"base": "ubuntu:26.10", "suffix": "~ubuntu26.10.1"},
}
DEFAULT_SERIES = ",".join(SERIES)

CHUNK = 1024 * 1024
MAX_DOWNLOAD = 512 * 1024 * 1024
ACTIVE_SOURCE_STATES = ("Published", "Pending")
FILE_FIELDS = {
    "Files": "MD5",
    "Checksums-Sha1": "SHA1",
    "Checksums-Sha256": "SHA256",
    "Checksums-Sha512": "SHA512",
}
DIGEST_LENGTHS = {"MD5": 32, "SHA1": 40, "SHA256": 64, "SHA512": 128}
SOURCE_NAME = "nekobox"
DPUT_TARGET_DEFAULT = DPUT_TARGET


class SourceUploadError(Exception):
    exit_code = 1


class UsageError(SourceUploadError):
    exit_code = 2


class NetworkError(SourceUploadError):
    exit_code = 3


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
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


def require(values: dict[str, str], key: str) -> str:
    value = values.get(key, "")
    if not value:
        raise UsageError(f"upstream.env does not define {key}")
    return value


def series_list(value: str) -> list[str]:
    items = [item.strip() for item in value.split(",") if item.strip()]
    unknown = [item for item in items if item not in SERIES]
    if unknown:
        raise UsageError(
            "unknown series: " + ", ".join(unknown)
            + " (supported: " + ", ".join(SERIES) + ")"
        )
    if not items:
        raise UsageError("no series selected")
    return items


def target_version(base_version: str, series: str) -> str:
    try:
        return base_version + SERIES[series]["suffix"]
    except KeyError as exc:
        raise UsageError(f"unknown series: {series}") from exc


def upstream_version(version: str) -> str:
    """Return the upstream part used in an orig tarball name."""
    without_epoch = version.split(":", 1)[-1]
    return without_epoch.rsplit("-", 1)[0] if "-" in without_epoch else without_epoch


def parse_deb822(text: str) -> list[dict[str, str]]:
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


def merge_file_entries(stanza: dict[str, str]) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for field_name, algorithm in FILE_FIELDS.items():
        raw = stanza.get(field_name)
        if not raw:
            continue
        for line in raw.splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if field_name == "Files" and len(parts) == 5:
                # .changes Files entries add section and priority:
                #   md5 size section priority name
                digest, size_text, name = parts[0], parts[1], parts[4]
            elif len(parts) == 3:
                digest, size_text, name = parts
            else:
                raise SourceUploadError(
                    f"{field_name} has a malformed entry: {line.strip()!r}"
                )
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+~_:-]*", name):
                raise SourceUploadError(f"unsafe file name {name!r}")
            if not size_text.isdigit():
                raise SourceUploadError(f"{name}: invalid size {size_text!r}")
            if not re.fullmatch(
                rf"[0-9a-fA-F]{{{DIGEST_LENGTHS[algorithm]}}}", digest
            ):
                raise SourceUploadError(f"{name}: malformed {algorithm} digest")
            size = int(size_text)
            entry = merged.setdefault(name, {"size": size, "hashes": {}})
            if entry["size"] != size:
                raise SourceUploadError(f"{name}: inconsistent size")
            entry["hashes"][algorithm] = digest.lower()
    return merged


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_file(path: Path) -> dict[str, str]:
    algorithms = {
        "MD5": hashlib.md5(),
        "SHA1": hashlib.sha1(),
        "SHA256": hashlib.sha256(),
        "SHA512": hashlib.sha512(),
    }
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            for digest in algorithms.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in algorithms.items()}


def tree_manifest(root: Path) -> str:
    entries: list[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            # Link permissions are not meaningful; canonicalise the target.
            entries.append(f"{rel}\tlink\t0777\t{os.readlink(path)}")
        elif path.is_file():
            # Keep the executable bit, which affects maintainer scripts and
            # debian/rules, but ignore umask/write-bit differences that
            # dpkg-source may normalise while extracting.
            mode = stat.S_IMODE(path.stat().st_mode)
            canonical = 0o755 if mode & 0o111 else 0o644
            entries.append(f"{rel}\tfile\t{canonical:04o}\t{sha256_file(path)}")
        elif path.is_dir():
            entries.append(f"{rel}\tdir\t0755")
    return "\n".join(entries) + "\n"


# --------------------------------------------------------------------------
# network
# --------------------------------------------------------------------------

# The PPA front end can answer 503 for minutes while no back end is available,
# so a short burst of retries only adds noise.  RETRY_DELAYS holds the pause
# before each retry, so its length plus one is the total attempt count.
TRANSIENT_HTTP_STATUSES = frozenset({500, 502, 503, 504})
RETRY_DELAYS = (5.0, 15.0, 30.0, 60.0, 120.0)


def _report_retry(url: str, attempt: int, reason: str) -> None:
    delay = RETRY_DELAYS[attempt]
    print(
        f"warning: {url}: attempt {attempt + 1}/{len(RETRY_DELAYS) + 1} failed "
        f"({reason}); retrying in {delay:g}s",
        file=sys.stderr,
        flush=True,
    )
    time.sleep(delay)


def _open(url: str, timeout: float):
    # Upload decisions and key registration must reflect current server state,
    # even behind a proxy that retains old API responses.
    if urllib.parse.urlsplit(url).hostname == "api.launchpad.net":
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}_fresh={time.time_ns()}"
    request = urllib.request.Request(
        url, headers={
            "User-Agent": "nekobox-ppa-source-upload/1",
            "Cache-Control": "no-cache",
        }
    )
    attempts = len(RETRY_DELAYS) + 1
    last_reason = ""
    for attempt in range(attempts):
        try:
            return urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            if code == 404:
                raise
            if code not in TRANSIENT_HTTP_STATUSES:
                raise NetworkError(f"HTTP {code} fetching {url}") from exc
            last_reason = f"HTTP {code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_reason = str(getattr(exc, "reason", exc))
        if attempt + 1 < attempts:
            _report_retry(url, attempt, last_reason)
    raise NetworkError(
        f"cannot fetch {url} after {attempts} attempts: {last_reason}"
    )


def fetch_json(url: str, timeout: float) -> Any:
    try:
        with _open(url, timeout) as response:
            data = response.read(MAX_DOWNLOAD)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkError(f"cannot parse JSON from {url}: {exc}") from exc


def download(url: str, destination: Path, timeout: float,
             expected_size: int | None = None) -> bool:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with _open(url, timeout) as response:
            length = response.headers.get("Content-Length")
            try:
                length_value = int(length) if length is not None else None
            except ValueError:
                length_value = None
            if length_value is not None and length_value > MAX_DOWNLOAD:
                raise SourceUploadError(
                    f"refusing download larger than {MAX_DOWNLOAD} bytes: {url}"
                )
            tmp = destination.with_name(destination.name + ".part")
            total = 0
            with tmp.open("wb") as handle:
                while True:
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOWNLOAD:
                        raise SourceUploadError(
                            f"download exceeded {MAX_DOWNLOAD} bytes: {url}"
                        )
                    handle.write(chunk)
            if expected_size is not None and total != expected_size:
                tmp.unlink(missing_ok=True)
                raise SourceUploadError(
                    f"{url}: size {total} does not match expected {expected_size}"
                )
            os.replace(tmp, destination)
            return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise NetworkError(f"HTTP {exc.code} fetching {url}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise NetworkError(f"cannot fetch {url}: {reason}") from exc


def collection(url: str, timeout: float) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    while url and url not in seen:
        seen.add(url)
        payload = fetch_json(url, timeout)
        if payload is None:
            break
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            raise NetworkError(f"unexpected collection payload from {url}")
        entries.extend(
            item for item in payload.get("entries", []) if isinstance(item, dict)
        )
        url = payload.get("next_collection_link") or ""
    return entries


# --------------------------------------------------------------------------
# Launchpad and PPA indexes
# --------------------------------------------------------------------------


def launchpad_sources(timeout: float) -> list[dict[str, Any]]:
    """Return source publications for every relevant archive status.

    Launchpad's getPublishedSources operation can filter by status; asking
    once without status is not enough to prove that an upload is absent.
    Query each status explicitly, then de-duplicate by record link.
    """
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for status in ("Published", "Pending", "Superseded", "Deleted", "Obsolete"):
        params = urllib.parse.urlencode(
            {
                "ws.op": "getPublishedSources",
                "source_name": SOURCE_NAME,
                "exact_match": "true",
                "status": status,
                "ws.size": "300",
            }
        )
        for entry in collection(f"{API_BASE}/{PPA_ARCHIVE}?{params}", timeout):
            key = str(
                entry.get("self_link")
                or entry.get("web_link")
                or (
                    source_series(entry),
                    source_version(entry),
                    source_status(entry),
                )
            )
            if key in seen:
                continue
            seen.add(key)
            entries.append(entry)
    return entries


def source_series(entry: dict[str, Any]) -> str | None:
    link = entry.get("distro_series_link")
    if not isinstance(link, str) or not link:
        return None
    return link.rstrip("/").rsplit("/", 1)[-1] or None


def source_version(entry: dict[str, Any]) -> str:
    return str(entry.get("source_package_version") or "")


def source_status(entry: dict[str, Any]) -> str:
    return str(entry.get("status") or "")


def sources_index(series: str, timeout: float) -> list[dict[str, str]]:
    url = f"{PPA_BASE}/dists/{series}/main/source/Sources.gz"
    tmp = Path(tempfile.mkdtemp(prefix="nekobox-sources-")) / "Sources.gz"
    try:
        if not download(url, tmp, timeout):
            return []
        try:
            text = gzip.decompress(tmp.read_bytes()).decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise SourceUploadError(f"{series}: cannot read Sources index: {exc}") from exc
        return parse_deb822(text)
    finally:
        shutil.rmtree(tmp.parent, ignore_errors=True)


def find_source_stanza(series: str, version: str, timeout: float) -> dict[str, str] | None:
    for stanza in sources_index(series, timeout):
        if (
            stanza.get("Package") == SOURCE_NAME
            and stanza.get("Version") == version
        ):
            return stanza
    return None


def safe_pool_path(directory: str) -> str:
    if not directory or not directory.startswith("pool/"):
        raise SourceUploadError(f"unsafe source Directory {directory!r}")
    parts = Path(directory).parts
    if ".." in parts or directory.startswith("/"):
        raise SourceUploadError(f"unsafe source Directory {directory!r}")
    return directory


def orig_from_dsc(text: str) -> dict[str, Any]:
    stanzas = parse_deb822(strip_clearsign(text))
    if len(stanzas) != 1:
        raise SourceUploadError("cannot parse exactly one .dsc stanza")
    dsc = stanzas[0]
    if dsc.get("Format") != "3.0 (quilt)":
        raise SourceUploadError(
            f"{dsc.get('Version')}: source format is {dsc.get('Format')!r}, "
            "expected 3.0 (quilt)"
        )
    files = merge_file_entries(dsc)
    orig = [name for name in files if ".orig.tar." in name]
    if len(orig) != 1:
        raise SourceUploadError(
            f"{dsc.get('Version')}: expected one orig tarball, found {len(orig)}"
        )
    name = orig[0]
    if not name.startswith(f"{SOURCE_NAME}_{upstream_version(str(dsc.get('Version') or ''))}.orig.tar."):
        raise SourceUploadError(
            f"{dsc.get('Version')}: unexpected orig tarball name {name!r}"
        )
    entry = files[name]
    sha256 = entry["hashes"].get("SHA256")
    sha512 = entry["hashes"].get("SHA512")
    if not sha256 and not sha512:
        raise SourceUploadError(f"{name}: no SHA256 or SHA512 in the published .dsc")
    result = {
        "name": name,
        "size": entry["size"],
        "source": dsc.get("Source"),
        "version": dsc.get("Version"),
    }
    if sha256:
        result["sha256"] = sha256
    if sha512:
        result["sha512"] = sha512
    return result


def archived_orig(version: str, timeout: float) -> dict[str, Any] | None:
    """Return the published orig metadata for an existing upstream version."""
    upstream = upstream_version(version)
    entries = [
        entry
        for entry in launchpad_sources(timeout)
        if upstream_version(source_version(entry)) == upstream
    ]
    if not entries:
        return None
    published = [entry for entry in entries if source_status(entry) == "Published"]
    if not published:
        statuses = {source_status(entry) for entry in entries}
        if statuses <= {"Deleted", "Obsolete"}:
            # No active source for this upstream version remains, so no
            # archived orig bytes constrain a new packaging revision.
            return None
        raise SourceUploadError(
            f"upstream {upstream} has no Published source (records: "
            f"{', '.join(sorted(statuses))}); wait for the archive to settle "
            "before building a new packaging revision"
        )

    records: list[dict[str, Any]] = []
    unavailable: list[str] = []
    for entry in published:
        series = source_series(entry)
        version_in_archive = source_version(entry)
        if series is None:
            continue
        try:
            stanza = find_source_stanza(series, version_in_archive, timeout)
            if stanza is None:
                raise SourceUploadError(
                    f"{series}: {version_in_archive} is Published but not in "
                    "Sources; retry after the index updates"
                )
            directory = safe_pool_path(stanza.get("Directory", ""))
            index_files = merge_file_entries(stanza)
            dsc_names = [name for name in index_files if name.endswith(".dsc")]
            if len(dsc_names) != 1:
                raise SourceUploadError(
                    f"{series}: expected one .dsc in Sources, "
                    f"found {len(dsc_names)}"
                )
            dsc_name = dsc_names[0]
            dsc_entry = index_files[dsc_name]
            strong = [
                (algorithm, dsc_entry["hashes"][algorithm])
                for algorithm in ("SHA256", "SHA512")
                if algorithm in dsc_entry["hashes"]
            ]
            if not strong:
                raise SourceUploadError(
                    f"{series}: {dsc_name} has no SHA256 or SHA512 in Sources"
                )
            cache = Path(tempfile.mkdtemp(prefix="nekobox-dsc-")) / dsc_name
            try:
                url = f"{PPA_BASE}/{directory}/{dsc_name}"
                if not download(url, cache, timeout, dsc_entry["size"]):
                    raise SourceUploadError(
                        f"{series}: published {dsc_name} is missing"
                    )
                actual = hash_file(cache)
                for algorithm, expected in strong:
                    if actual[algorithm] != expected:
                        raise SourceUploadError(
                            f"{series}: {dsc_name} {algorithm} mismatch "
                            f"(Sources {expected}, file {actual[algorithm]})"
                        )
                metadata = orig_from_dsc(cache.read_text(encoding="utf-8"))
            finally:
                shutil.rmtree(cache.parent, ignore_errors=True)
        except (NetworkError, SourceUploadError) as exc:
            # One series' frontend can be temporarily unavailable.  Use the
            # other published series' .dsc instead of blocking the whole
            # packaging revision; if none succeed, fail below.
            unavailable.append(f"{series}: {exc}")
            continue
        metadata.update(
            {
                "series": series,
                "dsc": dsc_name,
                "dsc_url": f"{PPA_BASE}/{directory}/{dsc_name}",
                "url": f"{PPA_BASE}/{directory}/{metadata['name']}",
                "directory": directory,
            }
        )
        records.append(metadata)

    if not records:
        detail = "; ".join(unavailable) if unavailable else "no published series"
        raise SourceUploadError(
            f"cannot resolve the archived orig for {upstream}: {detail}"
        )
    first = records[0]
    for record in records[1:]:
        for key in ("name", "size", "sha256", "sha512"):
            if key not in first or key not in record:
                continue
            if record[key] != first[key]:
                raise SourceUploadError(
                    "published series disagree on the orig tarball "
                    f"({first['series']} {first[key]!r} vs "
                    f"{record['series']} {record[key]!r}); refusing to guess"
                )
    result = dict(first)
    result["series"] = sorted({record["series"] for record in records})
    result["origin"] = "archive"
    return result


def _matches_orig(path: Path, meta: dict[str, Any]) -> bool:
    if path.stat().st_size != int(meta["size"]):
        return False
    actual = hash_file(path)
    if meta.get("sha256") and actual["SHA256"] != meta["sha256"]:
        return False
    if meta.get("sha512") and actual["SHA512"] != meta["sha512"]:
        return False
    return True


def cached_orig(meta: dict[str, Any], cache_dir: Path, timeout: float) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    destination = cache_dir / meta["name"]
    if destination.is_file():
        try:
            if _matches_orig(destination, meta):
                meta["sha256"] = hash_file(destination)["SHA256"]
                return destination
        except OSError:
            pass
        destination.unlink(missing_ok=True)
    if not download(meta["url"], destination, timeout, int(meta["size"])):
        raise NetworkError(f"archived orig tarball is missing: {meta['url']}")
    actual = hash_file(destination)
    for algorithm in ("SHA256", "SHA512"):
        expected = meta.get(algorithm.lower())
        if expected and actual[algorithm] != expected:
            destination.unlink(missing_ok=True)
            raise SourceUploadError(
                f"{destination.name}: {algorithm} mismatch "
                f"(published {expected}, downloaded {actual[algorithm]})"
            )
    if not meta.get("sha256") and not meta.get("sha512"):
        raise SourceUploadError(
            f"{destination.name}: the published .dsc supplied no strong digest"
        )
    meta["sha256"] = actual["SHA256"]
    return destination


# --------------------------------------------------------------------------
# plan / prepare
# --------------------------------------------------------------------------


def source_pin(repo: Path) -> tuple[dict[str, str], str, str, str]:
    env = read_env(repo / "upstream.env")
    version = require(env, "UPSTREAM_VERSION")
    revision = require(env, "DEBIAN_REVISION")
    return env, version, revision, f"{version}-{revision}"


def plan(repo: Path, selected: list[str], timeout: float,
         version: str | None = None, revision: str | None = None) -> dict[str, Any]:
    env, pinned_version, pinned_revision, pinned_base = source_pin(repo)
    requested_version = version or pinned_version
    requested_revision = revision or pinned_revision
    base_version = f"{requested_version}-{requested_revision}"

    # A candidate update is not on the PPA yet.  There is no archived orig to
    # reuse and every selected series needs the upload.
    if requested_version != pinned_version:
        series_entries = {
            series: {
                "series": series,
                "base": SERIES[series]["base"],
                "target_version": target_version(base_version, series),
                "needed": True,
                "action": "upload",
                "reason": "new upstream release",
                "source_status": None,
            }
            for series in selected
        }
        return {
            "schema_version": SCHEMA_VERSION,
            "version": requested_version,
            "revision": requested_revision,
            "base_version": base_version,
            "ppa": PPA_BASE,
            "orig": {
                "origin": "upstream",
                "name": f"{SOURCE_NAME}_{requested_version}.orig.tar.xz",
                "sha256": require(env, "UPSTREAM_SHA256"),
                "source_path": str(repo / "downloads" / require(env, "UPSTREAM_TARBALL")),
            },
            "series": series_entries,
            "needed_series": list(selected),
            "matrix": [
                {
                    "series": series,
                    "base": SERIES[series]["base"],
                    "target_version": target_version(base_version, series),
                    "needed": True,
                }
                for series in selected
            ],
            "publish_matrix": [
                {
                    "series": series,
                    "base": SERIES[series]["base"],
                    "target_version": target_version(base_version, series),
                }
                for series in selected
            ],
        }

    publications = launchpad_sources(timeout)
    series_entries: dict[str, Any] = {}
    needed: list[str] = []
    for series in selected:
        target = target_version(base_version, series)
        matching = [
            entry
            for entry in publications
            if source_series(entry) == series
            and source_version(entry) == target
        ]
        active = [
            entry for entry in matching if source_status(entry) in ACTIVE_SOURCE_STATES
        ]
        if active:
            status = source_status(active[0])
            series_entries[series] = {
                "series": series,
                "base": SERIES[series]["base"],
                "target_version": target,
                "needed": False,
                "action": "skip",
                "reason": f"already {status.lower()}",
                "source_status": status,
                "source_url": active[0].get("self_link") or active[0].get("web_link"),
            }
            continue
        if matching:
            status = source_status(matching[0])
            series_entries[series] = {
                "series": series,
                "base": SERIES[series]["base"],
                "target_version": target,
                "needed": False,
                "action": "skip",
                "reason": f"version already recorded as {status}; bump the revision",
                "source_status": status,
                "source_url": matching[0].get("self_link") or matching[0].get("web_link"),
            }
            continue
        needed.append(series)
        series_entries[series] = {
            "series": series,
            "base": SERIES[series]["base"],
            "target_version": target,
            "needed": True,
            "action": "upload",
            "reason": "not present on the PPA",
            "source_status": None,
        }

    orig_meta: dict[str, Any] | None = None
    if needed:
        orig_meta = archived_orig(pinned_version, timeout)
        if orig_meta is None:
            orig_meta = {
                "origin": "upstream",
                "name": f"{SOURCE_NAME}_{pinned_version}.orig.tar.xz",
                "sha256": require(env, "UPSTREAM_SHA256"),
                "source_path": str(repo / "downloads" / require(env, "UPSTREAM_TARBALL")),
            }

    return {
        "schema_version": SCHEMA_VERSION,
        "version": pinned_version,
        "revision": pinned_revision,
        "base_version": base_version,
        "ppa": PPA_BASE,
        "orig": orig_meta,
        "series": series_entries,
        "needed_series": needed,
        "matrix": [
            {
                "series": series,
                "base": SERIES[series]["base"],
                "target_version": target_version(base_version, series),
                "needed": series_entries[series]["needed"],
            }
            for series in selected
        ],
        "publish_matrix": [
            {
                "series": series,
                "base": SERIES[series]["base"],
                "target_version": target_version(base_version, series),
            }
            for series in needed
        ],
    }


def _orig_for_prepare(repo: Path, env: dict[str, str], version: str,
                      cache_dir: Path, timeout: float) -> dict[str, Any]:
    meta = archived_orig(version, timeout)
    if meta is None:
        tarball = repo / "downloads" / require(env, "UPSTREAM_TARBALL")
        expected = require(env, "UPSTREAM_SHA256")
        if not tarball.is_file():
            print(f"==> downloading {require(env, 'UPSTREAM_URL')}", file=sys.stderr)
            if not download(require(env, "UPSTREAM_URL"), tarball, timeout):
                raise NetworkError(f"upstream tarball is missing: {tarball}")
        actual = sha256_file(tarball)
        if actual != expected:
            raise SourceUploadError(
                f"{tarball.name}: SHA256 mismatch "
                f"(upstream.env {expected}, file {actual})"
            )
        return {
            "origin": "upstream",
            "path": tarball,
            "name": f"{SOURCE_NAME}_{version}.orig.tar.xz",
            "sha256": actual,
            "size": tarball.stat().st_size,
        }
    return {
        "origin": "archive",
        "path": cached_orig(meta, cache_dir, timeout),
        "name": meta["name"],
        "sha256": meta["sha256"],
        "size": int(meta["size"]),
        "url": meta["url"],
    }


def rewrite_changelog(text: str, version: str, distribution: str) -> str:
    lines = text.splitlines(keepends=True)
    if not lines:
        raise SourceUploadError("debian/changelog is empty")
    match = re.match(r"^(\S+) \(([^)]+)\) ([^;]+);(.*)$", lines[0].rstrip("\n"))
    if match is None:
        raise SourceUploadError(
            "debian/changelog first line is not 'source (version) series; ...'"
        )
    lines[0] = (
        f"{match.group(1)} ({version}) {distribution};{match.group(4)}"
        + ("\n" if lines[0].endswith("\n") else "")
    )
    return "".join(lines)


def _actual_orig(build_dir: Path, version: str) -> Path:
    matches = sorted(build_dir.glob(f"{SOURCE_NAME}_{version}.orig.tar.*"))
    if len(matches) != 1:
        raise SourceUploadError(
            f"expected one orig tarball for {version}, found "
            f"{[path.name for path in matches]}"
        )
    return matches[0]


def prepare(repo: Path, plan_data: dict[str, Any], series: str, timeout: float,
            prepare_script: Path | None = None,
            orig_override: dict[str, Any] | None = None) -> dict[str, Any]:
    entry = plan_data["series"].get(series)
    if entry is None:
        raise UsageError(f"series {series} is not in the plan")
    version = plan_data["version"]
    base_version = plan_data["base_version"]
    target = target_version(base_version, series)
    work = repo / "build" / "upload" / series
    result = {
        "schema_version": SCHEMA_VERSION,
        "series": series,
        "version": version,
        "base_version": base_version,
        "target_version": target,
        "distribution": series,
        "needed": bool(entry.get("needed")),
        "action": entry.get("action"),
    }

    env, pinned_version, pinned_revision, pinned_base = source_pin(repo)
    if pinned_version != version or pinned_base != base_version:
        raise UsageError(
            "the repository pin changed while preparing source: "
            f"{pinned_base} != {base_version}"
        )

    meta = orig_override or _orig_for_prepare(
        repo, env, version, repo / "build" / "upload-cache", timeout
    )
    args: list[str] = []
    if meta["origin"] == "archive":
        args = ["--orig-file", str(meta["path"]),
                "--orig-sha256", meta["sha256"]]
    script = prepare_script or (repo / "scripts" / "prepare-source.sh")
    proc = subprocess.run(
        [str(script), *args], cwd=repo, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    (work.parent.parent / "prepare-source.log").write_text(
        proc.stdout, encoding="utf-8"
    )
    if proc.returncode != 0:
        raise SourceUploadError(
            "scripts/prepare-source.sh failed; see build/prepare-source.log"
        )

    tree = repo / "build" / f"{SOURCE_NAME}-{version}"
    if not (tree / "debian" / "changelog").is_file():
        raise SourceUploadError(f"prepared source tree is missing: {tree}")
    actual_orig = _actual_orig(repo / "build", version)
    actual_sha = sha256_file(actual_orig)
    if meta["origin"] == "archive" and actual_sha != meta["sha256"]:
        raise SourceUploadError(
            f"{actual_orig.name}: prepared SHA256 {actual_sha} does not match "
            f"the archived orig {meta['sha256']}"
        )

    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    dest_tree = work / f"{SOURCE_NAME}-{version}"
    shutil.copytree(tree, dest_tree, symlinks=True)
    dest_orig = work / actual_orig.name
    shutil.copy2(actual_orig, dest_orig)
    changelog = dest_tree / "debian" / "changelog"
    changelog.write_text(
        rewrite_changelog(changelog.read_text(encoding="utf-8"), target, series),
        encoding="utf-8",
    )

    result.update(
        {
            "tree": str(dest_tree),
            "tree_name": dest_tree.name,
            "orig": {
                "origin": meta["origin"],
                "name": dest_orig.name,
                "sha256": actual_sha,
                "size": dest_orig.stat().st_size,
                "url": meta.get("url"),
            },
            "debian_manifest": tree_manifest(dest_tree / "debian"),
        }
    )
    (work / "prepare.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"prepared {series}: {target} "
        f"(orig {dest_orig.name} {actual_sha[:12]}… from {meta['origin']})"
    )
    return result


# --------------------------------------------------------------------------
# verification and signing
# --------------------------------------------------------------------------

def _verify_file(path: Path, entry: dict[str, Any], fields: Iterable[str]) -> None:
    if not path.is_file():
        raise SourceUploadError(f"{path.name}: listed in .changes but missing")
    if path.stat().st_size != entry["size"]:
        raise SourceUploadError(
            f"{path.name}: size {path.stat().st_size} != {entry['size']}"
        )
    actual = hash_file(path)
    for algorithm in fields:
        expected = entry["hashes"].get(algorithm)
        if expected and actual[algorithm] != expected:
            raise SourceUploadError(
                f"{path.name}: {algorithm} mismatch "
                f"({expected}, file {actual[algorithm]})"
            )


def verify_changes(changes: Path, expected: dict[str, Any]) -> dict[str, Any]:
    text = changes.read_text(encoding="utf-8")
    stanzas = parse_deb822(strip_clearsign(text))
    if len(stanzas) != 1:
        raise SourceUploadError(f"{changes.name}: cannot parse exactly one stanza")
    stanza = stanzas[0]
    series = expected["series"]
    target = expected["target_version"]
    if stanza.get("Format") not in (None, "1.8"):
        raise SourceUploadError(
            f"{changes.name}: Format {stanza.get('Format')!r}, expected 1.8"
        )
    if stanza.get("Source") != SOURCE_NAME:
        raise SourceUploadError(
            f"{changes.name}: Source {stanza.get('Source')!r}"
        )
    if stanza.get("Architecture") != "source":
        raise SourceUploadError(
            f"{changes.name}: Architecture {stanza.get('Architecture')!r}, "
            "expected source"
        )
    if stanza.get("Distribution") != series:
        raise SourceUploadError(
            f"{changes.name}: Distribution {stanza.get('Distribution')!r}, "
            f"expected {series}"
        )
    if stanza.get("Version") != target:
        raise SourceUploadError(
            f"{changes.name}: Version {stanza.get('Version')!r}, expected {target}"
        )

    files = merge_file_entries(stanza)
    if not files:
        raise SourceUploadError(f"{changes.name}: no files listed")
    binaries = [
        name for name in files
        if name.endswith((".deb", ".ddeb", ".udeb", ".tar.gz"))
        and ".orig.tar." not in name
    ]
    if binaries:
        raise SourceUploadError(
            f"{changes.name}: source upload lists binaries: {binaries}"
        )
    dscs = [name for name in files if name.endswith(".dsc")]
    origs = [name for name in files if ".orig.tar." in name]
    debtars = [name for name in files if ".debian.tar." in name]
    if len(dscs) != 1 or len(origs) != 1 or len(debtars) != 1:
        raise SourceUploadError(
            f"{changes.name}: expected one .dsc, one orig and one debian tarball; "
            f"found {dscs}, {origs}, {debtars}"
        )
    dsc = changes.parent / dscs[0]
    orig = changes.parent / origs[0]
    for path in (dsc, orig, changes.parent / debtars[0]):
        _verify_file(path, files[path.name], FILE_FIELDS.values())

    orig_expected = expected["orig"]
    if orig.name != orig_expected["name"]:
        raise SourceUploadError(
            f"{changes.name}: orig {orig.name!r}, expected {orig_expected['name']!r}"
        )
    if files[orig.name]["hashes"].get("SHA256") != orig_expected["sha256"]:
        raise SourceUploadError(
            f"{changes.name}: orig SHA256 does not match the prepared source"
        )

    dsc_stanzas = parse_deb822(strip_clearsign(dsc.read_text(encoding="utf-8")))
    if len(dsc_stanzas) != 1:
        raise SourceUploadError(f"{dsc.name}: cannot parse exactly one stanza")
    dsc_data = dsc_stanzas[0]
    if dsc_data.get("Format") != "3.0 (quilt)":
        raise SourceUploadError(
            f"{dsc.name}: Format {dsc_data.get('Format')!r}, expected 3.0 (quilt)"
        )
    if dsc_data.get("Source") != SOURCE_NAME or dsc_data.get("Version") != target:
        raise SourceUploadError(
            f"{dsc.name}: source/version do not match the .changes"
        )
    dsc_files = merge_file_entries(dsc_data)
    if origs[0] not in dsc_files:
        raise SourceUploadError(f"{dsc.name}: does not reference {origs[0]}")
    for algorithm in ("SHA1", "SHA256"):
        lhs = dsc_files[origs[0]]["hashes"].get(algorithm)
        rhs = files[origs[0]]["hashes"].get(algorithm)
        if lhs and rhs and lhs != rhs:
            raise SourceUploadError(
                f"{dsc.name}: {origs[0]} {algorithm} differs from the .changes"
            )
    if dsc_files[origs[0]]["hashes"].get("SHA256") != orig_expected["sha256"]:
        raise SourceUploadError(
            f"{dsc.name}: orig SHA256 does not match the prepared source"
        )
    return {
        "changes": str(changes),
        "dsc": str(dsc),
        "orig": str(orig),
        "debian_tar": str(changes.parent / debtars[0]),
        "files": sorted(files),
        "version": target,
        "distribution": series,
    }


def _find_one(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        raise SourceUploadError(
            f"expected one {pattern} in {directory}, found "
            f"{[path.name for path in matches]}"
        )
    return matches[0]


def sign(repo: Path, plan_data: dict[str, Any], series: str,
         keyid: str | None = None, wrapper: Path | None = None,
         unsigned: bool = False) -> dict[str, Any]:
    work = repo / "build" / "upload" / series
    prep_path = work / "prepare.json"
    if not prep_path.is_file():
        raise UsageError(f"{series}: run prepare first ({prep_path} is missing)")
    prep = json.loads(prep_path.read_text(encoding="utf-8"))
    if not prep.get("needed") and not unsigned:
        result = dict(prep, signed=False, action="skip")
        (work / "source.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        return result

    tree = Path(prep["tree"])
    if not (tree / "debian" / "changelog").is_file():
        raise SourceUploadError(f"{series}: prepared tree is missing: {tree}")
    orig = work / prep["orig"]["name"]
    if not orig.is_file():
        raise SourceUploadError(f"{series}: prepared orig is missing: {orig}")
    if sha256_file(orig) != prep["orig"]["sha256"]:
        raise SourceUploadError(
            f"{series}: prepared orig SHA256 changed since prepare"
        )
    # dpkg-genchanges writes this build artifact into the source tree; it is
    # not part of the uploaded debian tarball and must not make a rerun look
    # like a modified source tree.
    (tree / "debian" / "files").unlink(missing_ok=True)
    before_manifest = tree_manifest(tree / "debian")
    if prep.get("debian_manifest") and before_manifest != prep["debian_manifest"]:
        raise SourceUploadError(
            f"{series}: prepared debian/ changed since prepare; refusing to "
            "validate or sign a different tree"
        )

    changes = list(work.glob("*.changes"))
    for path in changes:
        path.unlink()
    for pattern in ("*.dsc", "*.debian.tar.*", "*_source.buildinfo"):
        for path in work.glob(pattern):
            path.unlink()

    command = ["dpkg-buildpackage", "-S", "-sa", "-d", "-nc"]
    if unsigned:
        command += ["-us", "-uc"]
    else:
        if not keyid:
            raise UsageError("--keyid is required for a signed source build")
        wrapper = wrapper or (repo / "scripts" / "gpg-sign-wrapper.sh")
        if not wrapper.is_file():
            raise UsageError(f"signing wrapper not found: {wrapper}")
        command += ["--sign-backend=gpg", f"-k{keyid}", f"-p{wrapper}"]
    env = dict(os.environ)
    proc = subprocess.run(
        command, cwd=tree, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    (work / "build.log").write_text(proc.stdout, encoding="utf-8")
    if proc.returncode != 0:
        raise SourceUploadError(
            f"{series}: dpkg-buildpackage failed; see {work / 'build.log'}"
        )
    (tree / "debian" / "files").unlink(missing_ok=True)

    target = prep["target_version"]
    changes_path = _find_one(work, f"{SOURCE_NAME}_{target}_source.changes")
    dsc_path = _find_one(work, f"{SOURCE_NAME}_{target}.dsc")
    expected = {
        "series": series,
        "target_version": target,
        "orig": prep["orig"],
    }
    verified = verify_changes(changes_path, expected)

    if not unsigned:
        for path in (dsc_path, changes_path):
            check = subprocess.run(
                ["gpg", "--batch", "--verify", str(path)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False,
            )
            if check.returncode != 0:
                raise SourceUploadError(
                    f"{path.name}: signature verification failed:\n{check.stdout}"
                )
        buildinfo = work / f"{SOURCE_NAME}_{target}_source.buildinfo"
        if buildinfo.is_file():
            check = subprocess.run(
                ["gpg", "--batch", "--verify", str(buildinfo)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False,
            )
            if check.returncode != 0:
                raise SourceUploadError(
                    f"{buildinfo.name}: signature verification failed"
                )

    # dpkg-source -x verifies the source package contents, not the signature.
    roundtrip = work / "roundtrip"
    shutil.rmtree(roundtrip, ignore_errors=True)
    extract = subprocess.run(
        ["dpkg-source", "-x", str(dsc_path), str(roundtrip)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    (work / "dpkg-source-extract.log").write_text(extract.stdout, encoding="utf-8")
    if extract.returncode != 0:
        raise SourceUploadError(
            f"{series}: cannot re-extract the signed source package"
        )
    for path in ("debian/control", "debian/rules", "core/server/go.mod",
                 "CMakeLists.txt"):
        if not (roundtrip / path).exists():
            raise SourceUploadError(
                f"{series}: re-extracted source is missing {path}"
            )
    after_manifest = tree_manifest(roundtrip / "debian")
    if before_manifest != after_manifest:
        raise SourceUploadError(
            f"{series}: re-extracted debian/ differs from the prepared tree"
        )
    shutil.rmtree(roundtrip, ignore_errors=True)

    result = {
        "schema_version": SCHEMA_VERSION,
        "series": series,
        "version": plan_data["version"],
        "base_version": plan_data["base_version"],
        "target_version": target,
        "distribution": series,
        "needed": bool(prep.get("needed")),
        "action": "validated-unsigned" if unsigned else "signed",
        "orig": prep["orig"],
        "changes": verified["changes"],
        "dsc": verified["dsc"],
        "debian_tar": verified["debian_tar"],
        "files": verified["files"],
        "signing_key": keyid or "",
        "signature_verified": not unsigned,
        "unsigned": unsigned,
    }
    (work / "source.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"signed {series}: {target} "
        f"({len(result['files'])} files, Architecture: source)"
    )
    return result


# --------------------------------------------------------------------------
# Launchpad key preflight and dput
# --------------------------------------------------------------------------


def normalize_fingerprint(value: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value).upper()


def preflight_key(fingerprint: str, timeout: float) -> dict[str, Any]:
    wanted = normalize_fingerprint(fingerprint)
    if len(wanted) < 16:
        raise UsageError(f"not a usable signing fingerprint: {fingerprint!r}")
    url = f"{API_BASE}/~{PPA_OWNER}/gpg_keys"
    payload = fetch_json(url, timeout)
    entries = []
    if isinstance(payload, dict):
        entries = [item for item in payload.get("entries", []) if isinstance(item, dict)]
    registered = []
    for entry in entries:
        full = normalize_fingerprint(str(entry.get("fingerprint") or ""))
        keyid = normalize_fingerprint(str(entry.get("keyid") or ""))
        active = entry.get("active", True)
        if active is not True:
            continue
        registered.append(full or keyid)
        if full and (full == wanted or full.endswith(wanted[-16:]) or wanted.endswith(full[-16:])):
            return {"fingerprint": full or keyid, "url": url}
        if keyid and (keyid == wanted[-16:] or keyid == wanted):
            return {"fingerprint": full or keyid, "url": url}
    if not entries:
        raise SourceUploadError(
            f"Launchpad account ~{PPA_OWNER} has no registered GPG key. "
            "Import the signing public key at https://launchpad.net/~/+editpgpkeys "
            "and confirm the Launchpad email before uploading."
        )
    raise SourceUploadError(
        f"signing key {wanted[-16:]} is not registered on ~{PPA_OWNER}; "
        f"registered fingerprints: {', '.join(registered) or 'none active'}"
    )


def launchpad_status(series: str, version: str, timeout: float) -> str | None:
    matching = [
        entry
        for entry in launchpad_sources(timeout)
        if source_series(entry) == series and source_version(entry) == version
    ]
    if not matching:
        return None
    for status in ACTIVE_SOURCE_STATES:
        for entry in matching:
            if source_status(entry) == status:
                return status
    return source_status(matching[0]) or "unknown"


def verify_signature(path: Path, expected: str | None = None) -> str:
    """Verify a clearsigned file immediately before dput.

    Returns the signing fingerprint reported by gpg.  A valid signature is
    required; when the source manifest names the expected primary key, the
    reported signer (or its 16-hex suffix for a signing subkey) must match.
    """
    proc = subprocess.run(
        ["gpg", "--batch", "--status-fd=1", "--verify", str(path)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    output = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 0:
        raise SourceUploadError(
            f"{path.name}: signature verification failed:\n{output.strip()}"
        )
    signer = ""
    for line in proc.stdout.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            signer = line.split()[2]
            break
    if not signer:
        raise SourceUploadError(
            f"{path.name}: gpg did not report a valid signature"
        )
    if expected:
        wanted = normalize_fingerprint(expected)
        actual = normalize_fingerprint(signer)
        if not (
            actual == wanted
            or actual.endswith(wanted[-16:])
            or wanted.endswith(actual[-16:])
        ):
            raise SourceUploadError(
                f"{path.name}: signed by {actual[-16:]}, expected {wanted[-16:]}"
            )
    return signer


def _wait_for_source(series: str, version: str, timeout: float,
                     wait_seconds: float) -> str | None:
    deadline = time.monotonic() + wait_seconds
    while True:
        status = launchpad_status(series, version, timeout)
        if status in ACTIVE_SOURCE_STATES:
            return status
        if status in ("Deleted", "Obsolete"):
            raise SourceUploadError(
                f"{series}: Launchpad recorded {version} as {status}"
            )
        if time.monotonic() >= deadline:
            return status
        time.sleep(5)


def upload(repo: Path, plan_data: dict[str, Any], series: str,
           dry_run: bool = False, wait_seconds: float = 90.0,
           timeout: float = 60.0, dput_target: str = DPUT_TARGET_DEFAULT) -> dict[str, Any]:
    work = repo / "build" / "upload" / series
    source_path = work / "source.json"
    if not source_path.is_file():
        raise UsageError(f"{series}: run sign first ({source_path} is missing)")
    source = json.loads(source_path.read_text(encoding="utf-8"))
    entry = plan_data.get("series", {}).get(series)
    if entry is None:
        raise UsageError(f"{series}: the plan has no entry for this series")
    if plan_data.get("version") != source.get("version"):
        raise UsageError(
            f"{series}: plan upstream {plan_data.get('version')!r} does not "
            f"match signed source {source.get('version')!r}"
        )
    if plan_data.get("base_version") != source.get("base_version"):
        raise UsageError(
            f"{series}: plan base version {plan_data.get('base_version')!r} "
            f"does not match signed source {source.get('base_version')!r}"
        )
    if entry.get("target_version") != source.get("target_version"):
        raise UsageError(
            f"{series}: plan target {entry.get('target_version')!r} does not "
            f"match signed source {source.get('target_version')!r}"
        )
    if source.get("series") != series or source.get("distribution") != series:
        raise UsageError(
            f"{series}: signed source names series/distribution "
            f"{source.get('series')!r}/{source.get('distribution')!r}"
        )
    if bool(entry.get("needed")) != bool(source.get("needed")):
        raise UsageError(
            f"{series}: plan says needed={entry.get('needed')!r} but the "
            f"signed source says needed={source.get('needed')!r}; replan"
        )
    if not source.get("needed"):
        return {"series": series, "action": "skip", "reason": "not needed"}
    if source.get("unsigned") or not source.get("signature_verified"):
        raise UsageError(
            f"{series}: refusing to upload an unsigned source package; run sign"
        )
    target = source["target_version"]
    changes = Path(source["changes"])
    dsc = Path(source["dsc"])
    expected = {
        "series": series,
        "target_version": target,
        "orig": source["orig"],
    }
    verify_changes(changes, expected)
    if not dry_run:
        # Re-verify the cleartext signatures immediately before handing the
        # files to dput.  dput repeats the check, but a stale/tampered
        # source.json must not get as far as an upload attempt.
        signer = source.get("signing_key") or None
        verify_signature(dsc, signer)
        verify_signature(changes, signer)

    existing = launchpad_status(series, target, timeout)
    if existing in ACTIVE_SOURCE_STATES:
        return {
            "series": series,
            "action": "skip",
            "reason": f"already {existing.lower()}",
            "archive_status": existing,
            "version": target,
        }

    if not dry_run:
        preflight_key(source.get("signing_key", ""), timeout)

    command = ["dput"]
    if dry_run:
        command.append("-s")
    command += [dput_target, str(changes)]
    proc = subprocess.run(
        command, cwd=work, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    (work / "dput.log").write_text(proc.stdout, encoding="utf-8")
    if proc.returncode != 0:
        # A duplicate upload after an earlier transfer may still be the right
        # outcome if Launchpad already accepted the version.
        status = _wait_for_source(series, target, timeout, min(wait_seconds, 30))
        if status in ACTIVE_SOURCE_STATES:
            return {
                "series": series,
                "action": "already-present",
                "archive_status": status,
                "version": target,
                "detail": "dput reported a duplicate; Launchpad has the version",
            }
        raise SourceUploadError(
            f"{series}: dput failed (see {work / 'dput.log'}); archive status "
            f"is {status or 'unknown'}"
        )

    status = _wait_for_source(series, target, timeout, wait_seconds)
    return {
        "series": series,
        "action": "dry-run" if dry_run else "transferred",
        "archive_status": status or "unknown",
        "version": target,
        "detail": (
            "dput transfer accepted; Launchpad archive acceptance is "
            "asynchronous"
        ),
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def write_json(path: Path | None, data: Any) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_plan(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise UsageError(f"cannot read plan {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise UsageError(f"{path}: invalid JSON: {exc}") from exc
    if data.get("schema_version") != SCHEMA_VERSION:
        raise UsageError(f"{path}: unsupported schema version")
    return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="source-upload.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--repo-root", default=str(Path(__file__).resolve().parent.parent)
    )
    parser.add_argument("--timeout", type=float, default=60.0)
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="decide which series need an upload")
    plan.add_argument("--json", help="write the plan as JSON")
    plan.add_argument("--series", default=DEFAULT_SERIES)
    plan.add_argument("--version", help="candidate version (default: upstream.env)")
    plan.add_argument("--revision", help="Debian revision (default: upstream.env)")

    prepare = sub.add_parser("prepare", help="build per-series source trees")
    prepare.add_argument("--plan", required=True)
    prepare.add_argument("--series", default=DEFAULT_SERIES)

    sign = sub.add_parser("sign", help="sign and verify a per-series source package")
    sign.add_argument("--plan", required=True)
    sign.add_argument("--series", default=DEFAULT_SERIES)
    sign.add_argument("--keyid")
    sign.add_argument("--wrapper")
    sign.add_argument("--unsigned", action="store_true")

    preflight = sub.add_parser("preflight", help="check the key on Launchpad")
    preflight.add_argument("--fingerprint", required=True)

    upload = sub.add_parser("upload", help="dput the verified source package")
    upload.add_argument("--plan", required=True)
    upload.add_argument("--series", required=True)
    upload.add_argument("--dry-run", action="store_true")
    upload.add_argument("--wait", type=float, default=90.0)
    upload.add_argument("--dput-target", default=DPUT_TARGET_DEFAULT)
    upload.add_argument("--json")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(args.repo_root).resolve()
    if args.timeout <= 0:
        print("error: --timeout must be greater than zero", file=sys.stderr)
        return 2
    try:
        if args.command == "plan":
            result = plan(
                repo, series_list(args.series), args.timeout,
                version=args.version, revision=args.revision,
            )
            write_json(Path(args.json) if args.json else None, result)
            for series, entry in result["series"].items():
                print(
                    f"{series}: {entry['action']} {entry['target_version']} "
                    f"({entry['reason']})"
                )
            if result["needed_series"]:
                print("needed: " + ",".join(result["needed_series"]))
            else:
                print("needed: none")
            return 0
        if args.command == "prepare":
            data = load_plan(Path(args.plan))
            for series in series_list(args.series):
                prepare(repo, data, series, args.timeout)
            return 0
        if args.command == "sign":
            data = load_plan(Path(args.plan))
            for series in series_list(args.series):
                sign(
                    repo, data, series,
                    keyid=args.keyid,
                    wrapper=Path(args.wrapper) if args.wrapper else None,
                    unsigned=args.unsigned,
                )
            return 0
        if args.command == "preflight":
            result = preflight_key(args.fingerprint, args.timeout)
            print(f"registered signing key: {result['fingerprint']}")
            return 0
        if args.command == "upload":
            data = load_plan(Path(args.plan))
            result = upload(
                repo, data, args.series,
                dry_run=args.dry_run,
                wait_seconds=args.wait,
                timeout=args.timeout,
                dput_target=args.dput_target,
            )
            write_json(Path(args.json) if args.json else None, result)
            print(
                f"{result['series']}: {result['action']} "
                f"{result.get('version', '')} "
                f"(archive: {result.get('archive_status', 'unknown')})"
            )
            return 0
    except SourceUploadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
