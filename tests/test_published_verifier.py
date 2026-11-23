"""Tests for scripts/verify-published.py and launchpad-publish helpers."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
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
    # Dataclasses resolve string annotations through sys.modules, so the
    # module must be registered before exec_module on newer Python versions.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


vp = load("verify_published", "verify-published.py")
lp = load("launchpad_publish", "launchpad-publish.py")


STONKING = """Package: nekobox
Section: net
Version: 5.11.28.3-2~ppa1~ubuntu26.10.1
Filename: pool/main/n/nekobox/nekobox_5.11.28.3-2~ppa1~ubuntu26.10.1_amd64.deb
Size: 21119220
SHA512: 4247a373959fdee7c953913bab4acfb98760262f34bf01b2649ea469b548b278aea38cf0280aa5d78f23109a7de68d13f0b96231550f6d9c4cc283ee7692b663
Description: Qt proxy client
"""

NOBLE = """Package: nekobox
Section: net
Version: 5.11.28.3-2~ppa1~ubuntu24.04.1
Filename: pool/main/n/nekobox/nekobox_5.11.28.3-2~ppa1~ubuntu24.04.1_amd64.deb
Size: 21186792
SHA256: 3d56eba9ba5dc480eb75670c4d0ca8d8d00384293b8b1906decaf3226e74ecf1
SHA512: 912498b7438216d1150fde3986f72d944e523a3e55add8002a0c5983fbcf98db40e15922e1e07bf975013a47602742a9a39455cf8371964e147f25f007b51af9
Description: Qt proxy client
"""

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)

SOURCE_INDEX = """Package: nekobox
Binary: nekobox
Version: 1.0-1~ubuntu24.04.1
Section: net
Format: 3.0 (quilt)
Directory: pool/main/n/nekobox
Files:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 10 nekobox_1.0.orig.tar.gz
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 20 nekobox_1.0-1~ubuntu24.04.1.debian.tar.xz
 cccccccccccccccccccccccccccccccc 30 nekobox_1.0-1~ubuntu24.04.1.dsc
Checksums-Sha1:
 1111111111111111111111111111111111111111 10 nekobox_1.0.orig.tar.gz
 2222222222222222222222222222222222222222 20 nekobox_1.0-1~ubuntu24.04.1.debian.tar.xz
 3333333333333333333333333333333333333333 30 nekobox_1.0-1~ubuntu24.04.1.dsc
Checksums-Sha256:
 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee 10 nekobox_1.0.orig.tar.gz
 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 20 nekobox_1.0-1~ubuntu24.04.1.debian.tar.xz
 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 30 nekobox_1.0-1~ubuntu24.04.1.dsc
"""

DSC = """Format: 3.0 (quilt)
Source: nekobox
Binary: nekobox
Architecture: amd64
Version: 1.0-1~ubuntu24.04.1
Maintainer: Test <test@example.com>
Files:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 10 nekobox_1.0.orig.tar.gz
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 20 nekobox_1.0-1~ubuntu24.04.1.debian.tar.xz
Checksums-Sha256:
 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee 10 nekobox_1.0.orig.tar.gz
 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 20 nekobox_1.0-1~ubuntu24.04.1.debian.tar.xz
"""


class VerifyPublishedTests(unittest.TestCase):
    def test_parse_packages_returns_stanzas(self):
        stanzas = vp.parse_packages(STONKING + "\n" + NOBLE)
        self.assertEqual(len(stanzas), 2)
        self.assertEqual(stanzas[0]["Package"], "nekobox")

    def test_select_package_requires_matching_base_version(self):
        stanzas = vp.parse_packages(NOBLE + "\n" + STONKING)
        found = vp.select_package(stanzas, "5.11.28.3-2~ppa1")
        self.assertIsNotNone(found)
        self.assertIsNone(vp.select_package(stanzas, "5.11.28.4-2~ppa1"))

    def test_stonking_sha512_only_is_a_strong_digest(self):
        package = vp.parse_packages(STONKING)[0]
        digests = vp.digests_for(package)
        self.assertIn("SHA512", digests)
        self.assertNotIn("SHA256", digests)

    def test_missing_strong_digest_is_rejected(self):
        with self.assertRaises(vp.VerifyError):
            vp.digests_for({"Package": "nekobox", "Version": "1"})

    def test_verify_hashes_checks_only_supplied_digests(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.deb"
            path.write_bytes(b"payload")
            sha512 = hashlib.sha512(b"payload").hexdigest()
            got256, got512 = vp.verify_hashes(path, {"SHA512": sha512})
            self.assertEqual(got512, sha512)
            self.assertEqual(len(got256), 64)
            with self.assertRaises(vp.VerifyError):
                vp.verify_hashes(path, {"SHA512": "0" * 128})

    def test_version_matches_series_suffix(self):
        self.assertTrue(
            vp.version_matches(
                "5.11.28.3-2~ppa1~ubuntu24.04.1", "5.11.28.3-2~ppa1"
            )
        )
        self.assertFalse(
            vp.version_matches(
                "5.11.28.4-2~ppa1~ubuntu24.04.1", "5.11.28.3-2~ppa1"
            )
        )

    def test_summary_includes_pending_series(self):
        result = {
            "base_version": "1-1",
            "series": ["noble", "stonking"],
            "results": {
                "noble": {
                    "status": "verified",
                    "published_version": "1-1~ubuntu24.04.1",
                    "sha256": "a" * 64,
                },
                "stonking": {"status": "pending", "detail": "not yet"},
            },
        }
        summary = vp.render_summary(result)
        self.assertIn("stonking", summary)
        self.assertIn("pending", summary)

    def test_summary_links_failed_build_evidence(self):
        result = {
            "base_version": "1-1",
            "series": ["noble"],
            "results": {
                "noble": {
                    "status": "failed",
                    "detail": "Launchpad build Failed to build",
                    "build_url": "https://launchpad.net/build/9",
                }
            },
        }
        summary = vp.render_summary(result)
        self.assertIn("failed", summary)
        self.assertIn("https://launchpad.net/build/9", summary)


class PublicationDecisionTests(unittest.TestCase):
    def build(self, state, hours_ago=1.0, **kwargs):
        kwargs.setdefault("url", "https://launchpad.net/build/1")
        kwargs.setdefault("series", "noble")
        return vp.BuildEvidence(
            state=state,
            created=NOW - timedelta(hours=hours_ago),
            **kwargs,
        )

    def recipe(self, deb_version="1-1", hours_ago=2.0, builds=()):
        return vp.RecipeEvidence(
            url="https://code.launchpad.net/~x/+recipe/nekobox",
            deb_version=deb_version,
            changed=NOW - timedelta(hours=hours_ago),
            builds=tuple(builds),
        )

    def source(self, status="Pending", hours_ago=2.0, builds=()):
        return vp.SourceEvidence(
            version="1-1~ubuntu24.04.1",
            status=status,
            created=NOW - timedelta(hours=hours_ago),
            url="https://launchpad.net/sourcepub/1",
            builds=tuple(builds),
        )

    def classify(self, source=None, builds=(), recipe=None, **kwargs):
        return vp.classify_publication(
            series="noble",
            base_version="1-1",
            source=source,
            builds=builds,
            recipe=recipe or self.recipe(),
            now=NOW,
            max_pending_hours=24,
            **kwargs,
        )

    def test_failed_source_build_fails_with_concrete_url(self):
        failed = self.build(
            "Failed to build", 0.5, url="https://launchpad.net/build/9"
        )
        result = self.classify(source=self.source(builds=(failed,)))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["build_url"], "https://launchpad.net/build/9")
        self.assertIn("Failed to build", result["detail"])

    def test_failed_archive_build_fails_without_a_source(self):
        failed = self.build(
            "Chroot problem",
            0.5,
            version="1-1~ubuntu24.04.1",
            url="https://launchpad.net/build/10",
        )
        result = self.classify(builds=(failed,))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["build_url"], "https://launchpad.net/build/10")

    def test_failed_recipe_build_is_detected_without_a_source(self):
        failed = self.build(
            "Failed to upload",
            0.5,
            url="https://launchpad.net/recipebuild/11",
        )
        result = self.classify(recipe=self.recipe(builds=(failed,)))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["build_url"], "https://launchpad.net/recipebuild/11"
        )

    def test_queued_build_is_pending_not_failure(self):
        queued = self.build("Needs building", 1.0)
        result = self.classify(source=self.source(builds=(queued,)))
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["build_state"], "Needs building")

    def test_dependency_wait_is_pending_until_stale(self):
        waiting = self.build("Dependency wait", 1.0)
        self.assertEqual(
            self.classify(source=self.source(builds=(waiting,)))["status"],
            "pending",
        )
        old = self.build("Dependency wait", 30.0)
        self.assertEqual(
            self.classify(
                source=self.source(hours_ago=30.0, builds=(old,))
            )["status"],
            "stale",
        )

    def test_successful_build_waiting_for_publication_is_pending(self):
        built = self.build("Successfully built", 3.0, built=NOW)
        result = self.classify(source=self.source(builds=(built,)))
        self.assertEqual(result["status"], "pending")

    def test_stale_pending_after_24_hours_is_failure(self):
        old = self.build("Needs building", 30.0)
        result = self.classify(
            source=self.source(hours_ago=30.0, builds=(old,))
        )
        self.assertEqual(result["status"], "stale")
        self.assertIn("no Launchpad activity", result["detail"])

    def test_zero_max_pending_disables_stale_detection(self):
        old = self.build("Needs building", 30.0)
        result = vp.classify_publication(
            series="noble",
            base_version="1-1",
            source=self.source(hours_ago=30.0, builds=(old,)),
            builds=(),
            recipe=self.recipe(),
            now=NOW,
            max_pending_hours=0,
        )
        self.assertEqual(result["status"], "pending")

    def test_unknown_build_state_is_rejected(self):
        new_state = self.build("Some new Launchpad state", 1.0)
        result = self.classify(source=self.source(builds=(new_state,)))
        self.assertEqual(result["status"], "failed")
        self.assertIn("unrecognised", result["detail"])

    def test_recipe_without_a_build_request_is_pending_then_stale(self):
        pending = self.classify(recipe=self.recipe(hours_ago=1.0))
        self.assertEqual(pending["status"], "pending")
        stale = self.classify(recipe=self.recipe(hours_ago=30.0))
        self.assertEqual(stale["status"], "stale")

    def test_recipe_mismatch_uses_the_pin_age(self):
        recipe = self.recipe(deb_version="1-0", hours_ago=1.0)
        recent = self.classify(
            recipe=recipe, pin_committed=NOW - timedelta(hours=1)
        )
        self.assertEqual(recent["status"], "pending")
        old = self.classify(
            recipe=recipe, pin_committed=NOW - timedelta(hours=30)
        )
        self.assertEqual(old["status"], "stale")
        self.assertIn("never started", old["detail"])

    def test_discover_series_rejects_unknown_targets(self):
        builds = [
            "https://api.launchpad.net/devel/ubuntu/noble",
            "https://api.launchpad.net/devel/ubuntu/oracular",
        ]
        with self.assertRaises(vp.UsageError):
            vp.discover_series(builds)

    def test_discover_series_returns_supported_order(self):
        builds = [
            "https://api.launchpad.net/devel/ubuntu/stonking",
            "https://api.launchpad.net/devel/ubuntu/noble",
            "https://api.launchpad.net/devel/ubuntu/resolute",
        ]
        self.assertEqual(
            vp.discover_series(builds),
            ["noble", "resolute", "stonking"],
        )

    def test_recipe_deb_version_is_parsed(self):
        text = (
            "# git-build-recipe format 0.4 deb-version 5.11.28.3-2~ppa1\n"
            "# comment\n"
            "lp:~x/+git/y upstream/5.11.28.3\n"
        )
        self.assertEqual(
            vp.parse_recipe_deb_version(text), "5.11.28.3-2~ppa1"
        )


class SourceMetadataTests(unittest.TestCase):
    def stanza(self):
        return vp.parse_packages(SOURCE_INDEX)[0]

    def test_quilt_orig_and_debian_are_accepted(self):
        metadata = vp.source_metadata(
            self.stanza(),
            DSC,
            "nekobox_1.0-1~ubuntu24.04.1.dsc",
            "1.0-1",
        )
        self.assertEqual(metadata["format"], "3.0 (quilt)")
        self.assertEqual(metadata["orig"], "nekobox_1.0.orig.tar.gz")
        self.assertEqual(
            metadata["debian"],
            "nekobox_1.0-1~ubuntu24.04.1.debian.tar.xz",
        )

    def test_native_source_is_rejected(self):
        with self.assertRaises(vp.VerifyError):
            vp.source_metadata(
                self.stanza(),
                DSC.replace("3.0 (quilt)", "3.0 (native)"),
                "nekobox_1.0-1~ubuntu24.04.1.dsc",
                "1.0-1",
            )

    def test_missing_debian_tarball_is_rejected(self):
        without_debian = "\n".join(
            line
            for line in DSC.splitlines()
            if ".debian.tar." not in line
        )
        with self.assertRaises(vp.VerifyError):
            vp.source_metadata(
                self.stanza(),
                without_debian + "\n",
                "nekobox_1.0-1~ubuntu24.04.1.dsc",
                "1.0-1",
            )

    def test_digest_mismatch_between_dsc_and_sources_is_rejected(self):
        tampered = DSC.replace("d" * 64, "f" * 64)
        with self.assertRaises(vp.VerifyError):
            vp.source_metadata(
                self.stanza(),
                tampered,
                "nekobox_1.0-1~ubuntu24.04.1.dsc",
                "1.0-1",
            )

    def test_unsafe_source_file_name_is_rejected(self):
        with self.assertRaises(vp.VerifyError):
            vp.merge_file_entries(
                {"Files": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 ../evil"}
            )


class FakeBuild:
    def __init__(self, state, series, version=None, url="https://launchpad.net/build/1"):
        self.buildstate = state
        self.datecreated = NOW - timedelta(hours=1)
        self.datebuilt = NOW - timedelta(minutes=30)
        self.web_link = url
        self.source_package_version = version
        self.distro_series_link = f"https://api.launchpad.net/1.0/ubuntu/{series}"


class FakeSource:
    def __init__(self, version, status, builds):
        self.source_package_version = version
        self.status = status
        self.date_created = NOW - timedelta(hours=2)
        self.date_made_pending = None
        self.date_published = NOW - timedelta(hours=1)
        self.web_link = "https://launchpad.net/sourcepub/1"
        self._builds = builds

    def getBuilds(self):
        return self._builds


class FakeArchive:
    def __init__(self, sources, builds):
        self.sources = sources
        self.builds = builds

    def getPublishedSources(self, **kwargs):
        return self.sources

    def getBuildRecords(self, **kwargs):
        return self.builds


class FakeRecipe:
    distroseries = ["https://api.launchpad.net/devel/ubuntu/noble"]
    recipe_text = "# git-build-recipe format 0.4 deb-version 1-1\n"
    date_last_modified = NOW
    web_link = "https://code.launchpad.net/~x/+recipe/nekobox"
    builds = [FakeBuild("Successfully built", "noble")]


class FakeLaunchpad:
    def __init__(self, archive, recipe):
        self.archive = archive
        self.recipe = recipe

    def load(self, path):
        if path == vp.ARCHIVE:
            return self.archive
        if path == vp.RECIPE:
            return self.recipe
        return object()


class LaunchpadContextTests(unittest.TestCase):
    def test_enabled_targets_do_not_come_from_build_history(self):
        recipe = FakeRecipe()
        recipe.distroseries = ["https://api.launchpad.net/devel/ubuntu/stonking"]
        context = vp.LaunchpadContext(FakeLaunchpad(FakeArchive([], []), recipe), 1)
        self.assertEqual(context.discover_series(), ["stonking"])

    def context(self):
        source = FakeSource(
            "1-1~ubuntu24.04.1",
            "Published",
            [FakeBuild("Successfully built", "noble",
                       version="1-1~ubuntu24.04.1")],
        )
        archive_build = FakeBuild(
            "Successfully built", "noble", version="1-1~ubuntu24.04.1",
            url="https://launchpad.net/build/2",
        )
        archive = FakeArchive([source], [archive_build])
        return vp.LaunchpadContext(
            FakeLaunchpad(archive, FakeRecipe()), 1
        )

    def test_context_reads_recipe_and_archive_without_writes(self):
        context = self.context()
        self.assertEqual(context.discover_series(), ["noble"])
        source = context.source_for("noble", "1-1")
        self.assertIsNotNone(source)
        self.assertEqual(source.status, "Published")
        self.assertEqual(len(source.builds), 1)
        builds = context.builds_for("noble", "1-1")
        self.assertEqual(len(builds), 1)
        self.assertEqual(builds[0].url, "https://launchpad.net/build/2")

    def test_context_ignores_other_versions(self):
        context = self.context()
        self.assertIsNone(context.source_for("noble", "2-1"))
        self.assertEqual(context.builds_for("noble", "2-1"), [])


class FakeContext:
    recipe = vp.RecipeEvidence(
        url="https://code.launchpad.net/~x/+recipe/nekobox",
        deb_version="1-1",
        changed=NOW,
        builds=(),
    )

    def __init__(self, series=("noble",)):
        self.series = list(series)

    def discover_series(self):
        return self.series


class RunTests(unittest.TestCase):
    def run_args(self, tmp, *extra):
        (tmp / "upstream.env").write_text(
            "UPSTREAM_VERSION=1.0\nDEBIAN_REVISION=1\n",
            encoding="utf-8",
        )
        args = [
            "--repo-root",
            str(tmp),
            "--json",
            str(tmp / "verification.json"),
            "--summary",
            str(tmp / "verification.md"),
        ]
        args.extend(extra)
        return vp.build_parser().parse_args(args)

    def run_with(self, entry, *extra, context=None):
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            args = self.run_args(tmp, *extra)
            with mock.patch.object(
                vp, "collect_launchpad_context", return_value=context or FakeContext()
            ), mock.patch.object(vp, "verify_series", return_value=dict(entry)):
                result = vp.run(args)
            written = json.loads(
                (tmp / "verification.json").read_text(encoding="utf-8")
            )
        return result, written

    def test_pending_remains_success_without_require_published(self):
        result, written = self.run_with(
            {"status": "pending", "detail": "waiting"}
        )
        self.assertTrue(result["ok"])
        self.assertEqual(written["results"]["noble"]["status"], "pending")
        self.assertEqual(written["schema_version"], vp.SCHEMA_VERSION)

    def test_pending_fails_with_require_published(self):
        result, _ = self.run_with(
            {"status": "pending", "detail": "waiting"},
            "--require-published",
        )
        self.assertFalse(result["ok"])

    def test_stale_and_failed_always_fail(self):
        for status in ("stale", "failed"):
            result, _ = self.run_with(
                {"status": status, "detail": "broken"}
            )
            self.assertFalse(result["ok"], status)

    def test_expect_series_must_match_enabled_recipe(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            args = self.run_args(
                Path(tmp_name), "--expect-series", "noble,resolute"
            )
            with mock.patch.object(
                vp, "collect_launchpad_context", return_value=FakeContext()
            ), mock.patch.object(vp, "verify_series", return_value={}):
                with self.assertRaises(vp.UsageError):
                    vp.run(args)

    def test_unknown_enabled_series_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            args = self.run_args(Path(tmp_name))
            with mock.patch.object(
                vp,
                "collect_launchpad_context",
                return_value=FakeContext(("oracular",)),
            ), mock.patch.object(vp, "verify_series", return_value={}):
                with self.assertRaises(vp.UsageError):
                    vp.run(args)


class LaunchpadPublishTests(unittest.TestCase):
    def test_recipe_code_drops_comments(self):
        text = """# git-build-recipe format 0.4 deb-version 1
# comment
lp:~x/+git/y upstream/1
nest-part packaging lp:~x/+git/y debian debian main
"""
        self.assertEqual(
            lp.recipe_code(text),
            "# git-build-recipe format 0.4 deb-version 1\n"
            "lp:~x/+git/y upstream/1\n"
            "nest-part packaging lp:~x/+git/y debian debian main\n",
        )

    def test_version_matches_prefix(self):
        self.assertTrue(lp.version_matches("1-1~ubuntu24.04.1", "1-1"))
        self.assertFalse(lp.version_matches("1-2~ubuntu24.04.1", "1-1"))


if __name__ == "__main__":
    unittest.main()
