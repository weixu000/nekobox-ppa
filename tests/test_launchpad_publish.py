"""Unit tests for scripts/launchpad-publish.py with a fake Launchpad API."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


lp = load("launchpad_publish", "launchpad-publish.py")

BASE = "1.0-2~ppa1"
NEXT = "1.1-2~ppa1"
NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)


def recipe_text(version: str = "1.0", base: str = BASE) -> str:
    return (
        f"{lp.RECIPE_HEADER_PREFIX}{base}\n"
        "#\n"
        "# A prose comment that must not be compared.\n"
        f"{lp.RECIPE_SOURCE} upstream/{version}\n"
        f"nest-part packaging {lp.RECIPE_SOURCE} debian debian {lp.PACKAGING_BRANCH}\n"
    )


def link(series: str) -> str:
    return f"https://api.launchpad.net/devel/ubuntu/{series}"


class FakeSeries:
    def __init__(self, name: str):
        self.name = name
        self.self_link = link(name)


class FakeSource:
    def __init__(
        self,
        version: str,
        status: str = "Published",
        date_published: datetime | None = None,
        date_created: datetime | None = None,
        date_superseded: datetime | None = None,
        date_removed: datetime | None = None,
    ):
        self.source_package_version = version
        self.status = status
        self.self_link = f"{lp.ARCHIVE}/+sourcepub/{version}"
        if date_published is not None:
            self.date_published = date_published
        if date_created is not None:
            self.date_created = date_created
        if date_superseded is not None:
            self.date_superseded = date_superseded
        if date_removed is not None:
            self.date_removed = date_removed


class FakeBuild:
    def __init__(
        self,
        series: str,
        state: str,
        created: datetime | str,
        use_entry: bool = True,
    ):
        if use_entry:
            self.distro_series = FakeSeries(series)
        else:
            self.distro_series = None
        self.distro_series_link = link(series)
        self.buildstate = state
        self.datecreated = created
        self.web_link = f"{lp.ARCHIVE}/+recipebuild/{series}-{state}"


class FakeRecipe:
    def __init__(
        self,
        text: str,
        base_version: str = BASE,
        enabled: tuple[str, ...] = ("noble", "resolute", "stonking"),
        builds: tuple[FakeBuild, ...] = (),
        modified: datetime = NOW,
    ):
        self.recipe_text = text
        self.deb_version_template = base_version
        self.distroseries = [link(name) for name in enabled]
        self.builds = list(builds)
        self.date_last_modified = modified
        self.web_link = "https://code.launchpad.net/~oblivionw26/+recipe/nekobox"
        self.saved = 0
        self.refreshed = 0
        self.set_recipe_text_calls = 0
        self.requested: list[tuple[str, str]] = []

    def lp_save(self) -> None:
        self.saved += 1
        # Launchpad recomputes the template from the header on save.
        header = self.recipe_text.splitlines()[0]
        self.deb_version_template = header[len(lp.RECIPE_HEADER_PREFIX) :].strip()

    def lp_refresh(self) -> None:
        self.refreshed += 1

    def setRecipeText(self, **kwargs) -> None:  # pragma: no cover - must not be used
        self.set_recipe_text_calls += 1

    def requestBuild(self, archive, distroseries, pocket):
        self.requested.append((distroseries.name, pocket))
        return FakeBuild(distroseries.name, "Needs building", datetime.now(timezone.utc))


class FakeArchive:
    def __init__(self, sources: dict[str, list[FakeSource]] | None = None):
        self.sources = sources or {}

    def getPublishedSources(self, source_name, distro_series, exact_match):
        return list(self.sources.get(distro_series.name, []))


class FakeLaunchpad:
    def __init__(self, recipe: FakeRecipe, archive: FakeArchive):
        self.recipe = recipe
        self.archive = archive

    def load(self, path: str):
        if path == lp.ARCHIVE:
            return self.archive
        if path == lp.RECIPE:
            return self.recipe
        if path.startswith("ubuntu/"):
            return FakeSeries(path.split("/", 1)[1])
        raise KeyError(path)


class TempRepo:
    def __init__(self, version: str = "1.0", base: str = BASE):
        self.version = version
        self.base = base

    def __enter__(self) -> Path:
        self.tmp = tempfile.TemporaryDirectory()
        repo = Path(self.tmp.name)
        (repo / "debian").mkdir()
        (repo / "upstream.env").write_text(
            "# test fixture\n"
            f"UPSTREAM_VERSION={self.version}\n"
            "DEBIAN_REVISION=2~ppa1\n"
            "DEBIAN_SOURCE=nekobox\n",
            encoding="utf-8",
        )
        (repo / "nekobox.recipe").write_text(
            recipe_text(self.version, self.base), encoding="utf-8"
        )
        (repo / "debian" / "changelog").write_text(
            f"nekobox ({self.base}) resolute; urgency=medium\n\n  * test\n",
            encoding="utf-8",
        )
        return repo

    def __exit__(self, *exc):
        self.tmp.cleanup()


def args_for(repo: Path, *extra: str) -> object:
    parser = lp.build_parser()
    return parser.parse_args(
        [
            "--repo-root",
            str(repo),
            "--mode",
            "mirror",
            "--version",
            "1.0",
            "--base-version",
            BASE,
            "--series",
            "noble,resolute,stonking",
            *extra,
        ]
    )


class TimestampTests(unittest.TestCase):
    def test_parse_timestamp_accepts_launchpad_datetime(self):
        aware = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        self.assertEqual(lp.parse_timestamp(aware), aware)
        naive = datetime(2026, 1, 2, 3, 4, 5)
        self.assertEqual(lp.parse_timestamp(naive), aware)

    def test_parse_timestamp_accepts_iso_strings(self):
        expected = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        self.assertEqual(lp.parse_timestamp("2026-01-02T03:04:05Z"), expected)
        self.assertEqual(lp.parse_timestamp("2026-01-02T03:04:05+00:00"), expected)

    def test_parse_timestamp_rejects_unusable_values(self):
        for value in (None, "", "not a date", 123):
            self.assertIsNone(lp.parse_timestamp(value))


class PublishedSourceTests(unittest.TestCase):
    def test_published_wins_over_pending_and_unrelated_versions_are_ignored(self):
        sources = [
            FakeSource(BASE + "~ubuntu24.04.1", "Pending"),
            FakeSource(BASE + "~ubuntu24.04.2", "Published"),
            FakeSource("0.9-1~ubuntu24.04.1", "Published"),
        ]
        found = lp.find_published(sources, BASE)
        self.assertIsNotNone(found)
        self.assertEqual(found.status, "Published")
        self.assertEqual(found.source_package_version, BASE + "~ubuntu24.04.2")

    def test_only_same_base_version_counts(self):
        sources = [FakeSource("1.0-1~ppa1~ubuntu24.04.1")]
        self.assertIsNone(lp.find_published(sources, BASE))

    def test_pending_exact_source_is_returned_without_a_duplicate(self):
        sources = [
            FakeSource(BASE + "~ubuntu24.04.1", "Pending"),
            FakeSource(BASE + "~ubuntu24.04.1", "Published"),
        ]
        found = lp.find_published(sources, BASE)
        self.assertEqual(found.status, "Published")


class RecipeSaveTests(unittest.TestCase):
    def test_update_recipe_uses_writable_property_and_lp_save(self):
        recipe = FakeRecipe(lp.recipe_code(recipe_text("1.0")))
        changed, saved_at = lp.update_recipe(
            recipe, recipe_text("1.1", NEXT), dry_run=False, now=NOW
        )
        self.assertTrue(changed)
        self.assertEqual(recipe.saved, 1)
        self.assertEqual(recipe.refreshed, 1)
        self.assertEqual(recipe.set_recipe_text_calls, 0)
        self.assertEqual(recipe.recipe_text, lp.recipe_code(recipe_text("1.1", NEXT)))
        self.assertIsInstance(saved_at, datetime)

    def test_update_recipe_is_a_noop_when_code_matches(self):
        recipe = FakeRecipe(lp.recipe_code(recipe_text("1.0")))
        changed, saved_at = lp.update_recipe(
            recipe, recipe_text("1.0"), dry_run=False, now=NOW
        )
        self.assertFalse(changed)
        self.assertEqual(recipe.saved, 0)
        self.assertEqual(saved_at, NOW)

    def test_dry_run_does_not_save(self):
        recipe = FakeRecipe(lp.recipe_code(recipe_text("1.0")))
        changed, _ = lp.update_recipe(
            recipe, recipe_text("1.1", NEXT), dry_run=True, now=NOW
        )
        self.assertTrue(changed)
        self.assertEqual(recipe.saved, 0)
        self.assertEqual(recipe.recipe_text, lp.recipe_code(recipe_text("1.0")))


class EnabledSeriesTests(unittest.TestCase):
    def test_enabled_series_reads_recipe_links(self):
        recipe = FakeRecipe(lp.recipe_code(recipe_text()), enabled=("noble", "resolute"))
        self.assertEqual(lp.enabled_series(recipe), {"noble", "resolute"})

    def test_enabled_series_accepts_resource_entries(self):
        recipe = FakeRecipe(lp.recipe_code(recipe_text()), enabled=())
        recipe.distroseries = [FakeSeries("noble")]
        self.assertEqual(lp.enabled_series(recipe), {"noble"})


class CutoverTests(unittest.TestCase):
    def test_changed_recipe_uses_the_save_time(self):
        saved = NOW - timedelta(minutes=1)
        recipe = FakeRecipe(lp.recipe_code(recipe_text()))
        self.assertEqual(
            lp.version_cutover(
                recipe, [], BASE, NOW, saved, recipe_changed=True
            ),
            saved,
        )

    def test_previous_version_publication_bounds_the_current_build(self):
        recipe = FakeRecipe(lp.recipe_code(recipe_text()), modified=NOW)
        previous = FakeSource(
            "0.9-1~ubuntu24.04.1",
            "Published",
            date_published=NOW - timedelta(minutes=20),
        )
        cutover = lp.version_cutover(
            recipe, [previous], BASE, NOW, NOW, recipe_changed=False
        )
        self.assertEqual(cutover, NOW - timedelta(minutes=20))

    def test_stored_template_mismatch_matches_no_build(self):
        recipe = FakeRecipe(
            lp.recipe_code(recipe_text("1.0")), base_version="0.9-1"
        )
        self.assertEqual(
            lp.version_cutover(
                recipe, [], BASE, NOW, NOW, recipe_changed=False
            ),
            NOW,
        )


class PendingBuildTests(unittest.TestCase):
    def test_older_version_build_is_not_treated_as_current(self):
        cutover = NOW - timedelta(minutes=30)
        recipe = FakeRecipe(
            lp.recipe_code(recipe_text()),
            builds=(
                FakeBuild("noble", "Currently building", NOW - timedelta(hours=2)),
                FakeBuild("noble", "Successfully built", NOW - timedelta(hours=3)),
            ),
        )
        self.assertIsNone(lp.pending_build_for(recipe, "noble", cutover))

    def test_in_flight_build_for_this_version_is_reused(self):
        cutover = NOW - timedelta(minutes=30)
        recipe = FakeRecipe(
            lp.recipe_code(recipe_text()),
            builds=(
                FakeBuild("noble", "Currently building", NOW - timedelta(minutes=5)),
                FakeBuild("resolute", "Currently building", NOW - timedelta(minutes=1)),
            ),
        )
        entry = lp.pending_build_for(recipe, "noble", cutover)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["action"], "already-requested")
        self.assertEqual(entry["buildstate"], "Currently building")

    def test_successfully_built_is_reused_to_avoid_a_duplicate(self):
        recipe = FakeRecipe(
            lp.recipe_code(recipe_text()),
            builds=(
                FakeBuild(
                    "noble",
                    "Successfully built",
                    (NOW - timedelta(minutes=3)).isoformat(),
                ),
            ),
        )
        entry = lp.pending_build_for(recipe, "noble", NOW - timedelta(minutes=30))
        self.assertEqual(entry["action"], "already-requested")

    def test_known_failure_is_surfaced(self):
        recipe = FakeRecipe(
            lp.recipe_code(recipe_text()),
            builds=(
                FakeBuild("noble", "Failed to build", NOW - timedelta(minutes=3)),
            ),
        )
        with self.assertRaises(lp.BuildFailure):
            lp.pending_build_for(recipe, "noble", NOW - timedelta(minutes=30))

    def test_unknown_state_is_not_silently_pending(self):
        recipe = FakeRecipe(
            lp.recipe_code(recipe_text()),
            builds=(
                FakeBuild("noble", "Something new", NOW - timedelta(minutes=3)),
            ),
        )
        with self.assertRaises(lp.BuildFailure):
            lp.pending_build_for(recipe, "noble", NOW - timedelta(minutes=30))

    def test_build_series_can_come_from_the_entry_or_the_link(self):
        entry = FakeBuild("noble", "Needs building", NOW)
        linked = FakeBuild("resolute", "Needs building", NOW, use_entry=False)
        self.assertEqual(lp.build_series_name(entry), "noble")
        self.assertEqual(lp.build_series_name(linked), "resolute")


class LocalValidationTests(unittest.TestCase):
    def test_valid_checkout_passes(self):
        with TempRepo() as repo:
            env = lp.read_env(repo / "upstream.env")
            text = lp.validate_local_inputs(repo, env, "1.0", "2~ppa1", BASE)
            self.assertEqual(text, recipe_text("1.0"))

    def test_recipe_header_must_match_the_pin(self):
        with self.assertRaises(lp.UsageError):
            lp.validate_recipe_text(recipe_text("1.0", "0.9-1"), "1.0", BASE)

    def test_recipe_refs_must_match_the_mirrored_branch(self):
        with self.assertRaises(lp.UsageError):
            lp.validate_recipe_text(recipe_text("0.9"), "1.0", BASE)

    def test_changelog_version_must_match(self):
        with TempRepo() as repo:
            (repo / "debian" / "changelog").write_text(
                "nekobox (0.9-1) resolute; urgency=medium\n", encoding="utf-8"
            )
            env = lp.read_env(repo / "upstream.env")
            with self.assertRaises(lp.UsageError):
                lp.validate_local_inputs(repo, env, "1.0", "2~ppa1", BASE)


class RunTests(unittest.TestCase):
    def _run(self, repo: Path, recipe: FakeRecipe, archive: FakeArchive, **kwargs):
        fake_lp = FakeLaunchpad(recipe, archive)
        with mock.patch.object(lp, "login", return_value=fake_lp):
            return lp.run(args_for(repo, *kwargs.get("extra", ())))

    def test_requests_only_enabled_series(self):
        with TempRepo() as repo:
            recipe = FakeRecipe(
                lp.recipe_code(recipe_text("0.9")),
                base_version=BASE,
                enabled=("noble",),
            )
            result = self._run(repo, recipe, FakeArchive())
        self.assertFalse(result["ok"])
        self.assertEqual(result["series"]["noble"]["action"], "requested")
        self.assertEqual(result["series"]["resolute"]["action"], "not-enabled")
        self.assertEqual(result["series"]["stonking"]["action"], "not-enabled")
        self.assertEqual(recipe.requested, [("noble", "Release")])
        self.assertEqual(recipe.saved, 1)
        self.assertEqual(recipe.set_recipe_text_calls, 0)

    def test_published_version_is_not_requested_again(self):
        with TempRepo() as repo:
            recipe = FakeRecipe(lp.recipe_code(recipe_text("1.0")))
            archive = FakeArchive(
                {
                    "noble": [
                        FakeSource(BASE + "~ubuntu24.04.1", "Published"),
                    ],
                    "resolute": [
                        FakeSource(BASE + "~ubuntu26.04.1", "Pending"),
                    ],
                    "stonking": [],
                }
            )
            result = self._run(repo, recipe, archive)
        self.assertTrue(result["ok"])
        self.assertEqual(result["series"]["noble"]["action"], "already-published")
        self.assertEqual(
            result["series"]["resolute"]["action"], "already-pending-upload"
        )
        self.assertEqual(result["series"]["stonking"]["action"], "requested")
        self.assertEqual(recipe.requested, [("stonking", "Release")])

    def test_existing_in_flight_build_is_reused(self):
        with TempRepo() as repo:
            recipe = FakeRecipe(
                lp.recipe_code(recipe_text("1.0")),
                builds=(
                    FakeBuild(
                        "noble", "Currently building", datetime.now(timezone.utc)
                    ),
                ),
            )
            result = self._run(
                repo,
                recipe,
                FakeArchive(),
                extra=("--series", "noble"),
            )
        self.assertEqual(result["series"]["noble"]["action"], "already-requested")
        self.assertEqual(recipe.requested, [])

    def test_failed_build_fails_the_run(self):
        with TempRepo() as repo:
            recipe = FakeRecipe(
                lp.recipe_code(recipe_text("1.0")),
                builds=(
                    FakeBuild(
                        "noble", "Failed to build", datetime.now(timezone.utc)
                    ),
                ),
            )
            result = self._run(
                repo,
                recipe,
                FakeArchive(),
                extra=("--series", "noble"),
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["series"]["noble"]["action"], "failed")
        self.assertEqual(recipe.requested, [])

    def test_mismatched_local_pin_is_rejected_before_login(self):
        with TempRepo() as repo:
            parser = lp.build_parser()
            args = parser.parse_args(
                [
                    "--repo-root",
                    str(repo),
                    "--version",
                    "9.9",
                    "--base-version",
                    "9.9-2~ppa1",
                    "--series",
                    "noble",
                ]
            )
            with mock.patch.object(lp, "login", side_effect=AssertionError("login")):
                with self.assertRaises(lp.UsageError):
                    lp.run(args)


if __name__ == "__main__":
    unittest.main()
