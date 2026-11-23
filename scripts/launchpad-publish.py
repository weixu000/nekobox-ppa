#!/usr/bin/env python3
"""Update the Launchpad recipe and request builds for validated refs.

This runs after the workflow has pushed the validated main and upstream
branch/tag to Launchpad.  It:

  * validates the local pin, recipe header, changelog version and recipe refs
    before touching Launchpad;
  * compares the local nekobox.recipe (comment lines ignored) with the recipe
    stored on Launchpad and updates it if needed;
  * reads the recipe's enabled series and refuses to request a build for any
    series the recipe is not configured for;
  * checks each supported series for an already published or pending source of
    this base version;
  * checks for an in-flight build created after this version became current,
    and surfaces a failed build instead of waiting on it forever;
  * only then calls requestBuild for that series.

That makes a "mirror current" run idempotent: it never requests a duplicate
build for a version that is already published, already uploaded or already in
flight, and it never treats a build of an older version as the current one.

Usage:
    scripts/launchpad-publish.py --mode auto --credentials FILE
    scripts/launchpad-publish.py --mode mirror --dry-run
    scripts/launchpad-publish.py --mode auto --no-request-builds

The credentials file is a launchpadlib credential file.  It is never printed.
Exit codes: 0 success, 1 API/build request failure, 2 usage.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Launchpad's devel API exposes recipe_text as a writable property and the
# git recipe fields used below.  The 1.0 API's recipe operation set differs
# (it still advertises setRecipeText), so use one version consistently.
API_VERSION = "devel"
SERIES = ("noble", "resolute", "stonking")
ARCHIVE = "~oblivionw26/+archive/ubuntu/nekobox"
RECIPE = "~oblivionw26/+recipe/nekobox"
RECIPE_HEADER_PREFIX = "# git-build-recipe format 0.4 deb-version "
RECIPE_SOURCE = "lp:~oblivionw26/+git/nekobox-ppa"
PACKAGING_BRANCH = "main"
CHANGELOG_RE = re.compile(r"^([^\s(]+) \(([^)]+)\)")

# Build states from Launchpad's source_package_recipe_build representation.
IN_FLIGHT_STATES = frozenset(
    {
        "Needs building",
        "Dependency wait",
        "Currently building",
        "Uploading build",
        "Gathering build output",
    }
)
SUCCESSFUL_BUILD_STATE = "Successfully built"
FAILED_BUILD_STATES = frozenset(
    {
        "Failed to build",
        "Chroot problem",
        "Failed to upload",
        "Cancelled build",
        "Cancelling build",
        "Build for superseded Source",
    }
)


class PublishError(Exception):
    exit_code = 1


class UsageError(PublishError):
    exit_code = 2


class BuildFailure(PublishError):
    """A build for the requested version already failed."""


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


def recipe_code(text: str) -> str:
    """Return the recipe without prose comments.

    The first git-build-recipe line is a comment syntactically, but it carries
    the required deb-version header, so it must be preserved.
    """
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#") and not stripped.startswith(
            "# git-build-recipe format"
        ):
            continue
        lines.append(line.rstrip())
    return "\n".join(lines) + "\n"


def parse_timestamp(value: Any) -> datetime | None:
    """Return an aware UTC datetime for launchpadlib or string timestamps.

    launchpadlib returns datetime objects for date fields; older code assumed
    ISO strings, which silently disabled pending-build detection.
    """
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


def version_matches(published: str, base_version: str) -> bool:
    return published == base_version or published.startswith(base_version + "~")


def link_name(value: Any) -> str | None:
    """Return the last path segment of an API link, or a resource's name."""
    if value is None:
        return None
    if isinstance(value, str):
        name = value.rstrip("/").rsplit("/", 1)[-1]
        return name or None
    name = getattr(value, "name", None)
    if isinstance(name, str) and name:
        return name
    link = getattr(value, "self_link", None)
    if isinstance(link, str):
        return link.rstrip("/").rsplit("/", 1)[-1] or None
    return None


def enabled_series(recipe) -> set[str]:
    """Return the series the Launchpad recipe is configured to build for."""
    entries = getattr(recipe, "distroseries", None) or []
    if isinstance(entries, (str, bytes)):
        entries = [entries]
    return {
        name
        for entry in entries
        if (name := link_name(entry)) is not None
    }


def build_series_name(build) -> str | None:
    """Return the build's distro series name using real API attributes."""
    name = link_name(getattr(build, "distro_series", None))
    if name is not None:
        return name
    return link_name(getattr(build, "distro_series_link", None))


def source_activity_time(source) -> datetime | None:
    """Return the latest known activity time for a source publication."""
    latest: datetime | None = None
    for attribute in ("date_published", "date_created", "date_superseded", "date_removed"):
        timestamp = parse_timestamp(getattr(source, attribute, None))
        if timestamp is not None and (latest is None or timestamp > latest):
            latest = timestamp
    return latest


def find_published(sources, base_version: str):
    """Return the published source for this version, else a pending upload.

    A Published source wins over a Pending one so a duplicate exact source is
    never reported as pending.
    """
    published = None
    pending = None
    for source in sources:
        version = getattr(source, "source_package_version", "")
        if not version_matches(version, base_version):
            continue
        status = getattr(source, "status", None)
        if status == "Published" and published is None:
            published = source
        elif status == "Pending" and pending is None:
            pending = source
    return published or pending


def version_cutover(
    recipe,
    sources,
    base_version: str,
    now: datetime,
    saved_at: datetime,
    recipe_changed: bool,
) -> datetime:
    """Return the earliest time a build can belong to this recipe version.

    If this run changed the recipe, only builds created after that save can be
    for the new text.  Otherwise use the latest activity of any other version
    in this series, falling back to the most recent request window.  A plain
    24-hour window would misread an unrelated previous version's build.
    """
    if recipe_changed:
        return saved_at
    if getattr(recipe, "deb_version_template", None) != base_version:
        # The stored recipe does not pin this version, so no build can be
        # attributed to it.  A real run rejects this before requesting.
        return now
    other_activity: datetime | None = None
    for source in sources:
        if version_matches(
            getattr(source, "source_package_version", ""), base_version
        ):
            continue
        timestamp = source_activity_time(source)
        if timestamp is not None and (
            other_activity is None or timestamp > other_activity
        ):
            other_activity = timestamp
    modified = parse_timestamp(getattr(recipe, "date_last_modified", None)) or now
    recent_window = min(modified, now) - timedelta(minutes=30)
    if other_activity is not None and other_activity > recent_window:
        return other_activity
    return recent_window


def pending_build_for(recipe, series_name: str, cutover: datetime) -> dict[str, Any] | None:
    """Return an existing build for this version, or raise on a failure.

    Only builds created at or after the inferred version cutover are considered.
    Recipe build entries do not expose a version; source publications provide
    the stronger exact-version check before this conservative deduplication.
    """
    candidates: list[tuple[datetime, Any]] = []
    for build in getattr(recipe, "builds", None) or []:
        if build_series_name(build) != series_name:
            continue
        created = parse_timestamp(getattr(build, "datecreated", None))
        if created is None or created < cutover:
            continue
        candidates.append((created, build))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    build = candidates[0][1]
    state = getattr(build, "buildstate", "")
    link = getattr(build, "web_link", None) or getattr(build, "self_link", None) or ""
    if state in IN_FLIGHT_STATES or state == SUCCESSFUL_BUILD_STATE:
        return {
            "action": "already-requested",
            "buildstate": state,
            "build": link,
        }
    if state in FAILED_BUILD_STATES:
        raise BuildFailure(
            f"{series_name}: the build for this version is {state!r} ({link})"
        )
    raise BuildFailure(
        f"{series_name}: unknown recipe build state {state!r} ({link})"
    )


def validate_recipe_text(text: str, version: str, base_version: str) -> None:
    """Check the local recipe header and the refs the mirror should provide."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith(RECIPE_HEADER_PREFIX):
        raise UsageError(
            f"nekobox.recipe line 1 must start with {RECIPE_HEADER_PREFIX!r}"
        )
    header_version = lines[0][len(RECIPE_HEADER_PREFIX) :].strip()
    if header_version != base_version:
        raise UsageError(
            f"nekobox.recipe pins {header_version!r}, expected {base_version!r}"
        )

    code = [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]
    expected_source = f"{RECIPE_SOURCE} upstream/{version}"
    expected_packaging = (
        f"nest-part packaging {RECIPE_SOURCE} debian debian {PACKAGING_BRANCH}"
    )
    if len(code) != 2:
        raise UsageError(
            f"nekobox.recipe must contain exactly two non-comment lines, found {len(code)}"
        )
    if code[0] != expected_source:
        raise UsageError(
            f"nekobox.recipe source line must be {expected_source!r}, got {code[0]!r}"
        )
    if code[1] != expected_packaging:
        raise UsageError(
            f"nekobox.recipe packaging line must be {expected_packaging!r}, "
            f"got {code[1]!r}"
        )


def validate_local_inputs(
    repo: Path,
    env: dict[str, str],
    version: str,
    revision: str,
    base_version: str,
) -> str:
    """Validate the pin, recipe header/refs and changelog before any write."""
    if env.get("UPSTREAM_VERSION") != version:
        raise UsageError(
            "upstream.env UPSTREAM_VERSION does not match the requested version"
        )
    if env.get("DEBIAN_REVISION") != revision:
        raise UsageError("upstream.env DEBIAN_REVISION changed while parsing")
    if base_version != f"{version}-{revision}":
        raise UsageError(
            f"base version {base_version!r} does not match upstream.env "
            f"({version}-{revision})"
        )

    try:
        recipe_text = (repo / "nekobox.recipe").read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot read nekobox.recipe: {exc}") from exc
    validate_recipe_text(recipe_text, version, base_version)

    try:
        changelog = (repo / "debian" / "changelog").read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot read debian/changelog: {exc}") from exc
    first = next((line for line in changelog.splitlines() if line.strip()), "")
    match = CHANGELOG_RE.match(first)
    if match is None:
        raise UsageError("debian/changelog first line has no source/version")
    source_name = env.get("DEBIAN_SOURCE", "nekobox")
    if match.group(1) != source_name:
        raise UsageError(
            f"debian/changelog source is {match.group(1)!r}, expected {source_name!r}"
        )
    if match.group(2) != base_version:
        raise UsageError(
            f"debian/changelog version is {match.group(2)!r}, "
            f"expected {base_version!r}"
        )
    return recipe_text


def login(credentials: str | None, application_name: str, dry_run: bool):
    from launchpadlib.launchpad import Launchpad

    if credentials is None:
        credentials = os.environ.get("LP_CREDENTIALS_FILE")
    if credentials is None:
        if not dry_run:
            raise UsageError(
                "--credentials or LP_CREDENTIALS_FILE is required for a write run"
            )
        return Launchpad.login_anonymously(
            application_name, "production", version=API_VERSION
        )
    path = Path(credentials)
    if not path.is_file() or path.stat().st_size == 0:
        raise UsageError(f"credentials file is missing or empty: {path}")
    # The credential file is portable between machines.  application_name is
    # explicit so a stored consumer key is used exactly as intended.
    return Launchpad.login_with(
        application_name,
        "production",
        credentials_file=str(path),
        version=API_VERSION,
    )


def update_recipe(
    recipe, local_text: str, dry_run: bool, now: datetime
) -> tuple[bool, datetime]:
    """Store the recipe text through the writable property and lp_save."""
    wanted = recipe_code(local_text)
    current = getattr(recipe, "recipe_text", "") or ""
    if recipe_code(current) == wanted:
        return False, now
    if dry_run:
        return True, now
    recipe.recipe_text = wanted
    recipe.lp_save()
    recipe.lp_refresh()
    if recipe_code(getattr(recipe, "recipe_text", "") or "") != wanted:
        raise PublishError("Launchpad did not store the requested recipe text")
    return True, datetime.now(timezone.utc)


def request_build(recipe, archive, series, dry_run: bool) -> dict[str, Any]:
    if dry_run:
        return {"action": "dry-run-request"}
    build = recipe.requestBuild(
        archive=archive,
        distroseries=series,
        pocket="Release",
    )
    return {
        "action": "requested",
        "build": build.web_link,
        "state": build.buildstate,
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(args.repo_root).resolve()
    env = read_env(repo / "upstream.env")
    version = args.version or env.get("UPSTREAM_VERSION", "")
    revision = env.get("DEBIAN_REVISION", "")
    if not version or not revision:
        raise UsageError("upstream.env must define UPSTREAM_VERSION and DEBIAN_REVISION")
    base_version = args.base_version or f"{version}-{revision}"

    series_list = [item.strip() for item in args.series.split(",") if item.strip()]
    unknown = [item for item in series_list if item not in SERIES]
    if unknown:
        raise UsageError(f"unknown series: {', '.join(unknown)}")
    if not series_list:
        raise UsageError("--series selected no series")

    # Everything that can be checked locally is checked before the login, so a
    # stale pin or a divergent recipe never reaches a Launchpad write.
    recipe_text = validate_local_inputs(
        repo, env, version, revision, base_version
    )

    lp = login(args.credentials, args.application_name, args.dry_run)
    archive = lp.load(ARCHIVE)
    recipe = lp.load(RECIPE)
    now = datetime.now(timezone.utc)
    configured = enabled_series(recipe)

    result: dict[str, Any] = {
        "schema_version": 1,
        "mode": args.mode,
        "dry_run": bool(args.dry_run),
        "version": version,
        "base_version": base_version,
        "recipe_url": recipe.web_link,
        "enabled_series": sorted(configured),
        "series": {},
        "ok": True,
    }
    try:
        changed, saved_at = update_recipe(
            recipe, recipe_text, args.dry_run, now
        )
        result["recipe_updated"] = changed
        if changed:
            result["recipe_update_url"] = recipe.web_link
        if not args.dry_run:
            stored_version = getattr(recipe, "deb_version_template", None)
            if stored_version != base_version:
                raise PublishError(
                    "Launchpad recipe pins "
                    f"{stored_version!r}, expected {base_version!r}"
                )
    except Exception as exc:  # noqa: BLE001 - report API failure without secrets
        result["ok"] = False
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    for name in series_list:
        entry: dict[str, Any] = {"series": name}
        if name not in configured:
            result["ok"] = False
            entry.update(
                {
                    "action": "not-enabled",
                    "error": (
                        f"{name} is not enabled on the Launchpad recipe; "
                        "refusing to request a build"
                    ),
                }
            )
            result["series"][name] = entry
            continue
        try:
            series = lp.load(f"ubuntu/{name}")
            sources = list(
                archive.getPublishedSources(
                    source_name="nekobox",
                    distro_series=series,
                    exact_match=True,
                )
            )
            published = find_published(sources, base_version)
            if published is not None:
                status = getattr(published, "status", "Published")
                entry.update(
                    {
                        "action": (
                            "already-pending-upload"
                            if status == "Pending"
                            else "already-published"
                        ),
                        "published_version": published.source_package_version,
                        "source_status": status,
                        "source_url": published.self_link,
                    }
                )
            else:
                cutover = version_cutover(
                    recipe,
                    sources,
                    base_version,
                    now,
                    saved_at,
                    changed,
                )
                existing = pending_build_for(recipe, name, cutover)
                if existing is not None:
                    entry.update(existing)
                elif not args.request_builds:
                    entry.update({"action": "not-requested"})
                else:
                    entry.update(request_build(recipe, archive, series, args.dry_run))
        except Exception as exc:  # noqa: BLE001
            result["ok"] = False
            entry.update(
                {"action": "failed", "error": f"{type(exc).__name__}: {exc}"}
            )
        result["series"][name] = entry

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="launchpad-publish.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--mode", choices=("auto", "mirror"), default="auto")
    parser.add_argument("--version", help="upstream version (default: upstream.env)")
    parser.add_argument("--base-version", help="Debian base version to check")
    parser.add_argument("--series", default=",".join(SERIES))
    parser.add_argument("--credentials", help="launchpadlib credential file")
    parser.add_argument(
        "--application-name",
        default=os.environ.get("LP_APPLICATION_NAME", "nekobox-ppa-ci"),
        help="OAuth application name used with launchpadlib",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--no-request-builds",
        dest="request_builds",
        action="store_false",
        help="update the recipe but do not request builds",
    )
    parser.set_defaults(request_builds=True)
    parser.add_argument("--json", help="write the result as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = run(args)
    except PublishError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except Exception as exc:  # noqa: BLE001 - keep secrets out of tracebacks
        print(f"error: Launchpad API failure: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        f"recipe_updated={result.get('recipe_updated')} "
        f"ok={result['ok']}"
    )
    for name, entry in result["series"].items():
        detail = entry.get("build") or entry.get("published_version") or entry.get("buildstate", "")
        print(f"{name}: {entry['action']} {detail}".rstrip())
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
