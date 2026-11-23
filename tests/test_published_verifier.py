"""Tests for scripts/verify-published.py."""

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
            "ppa": vp.PPA_BASE,
            "series": ["noble", "stonking"],
            "enabled_series": ["noble", "resolute", "stonking"],
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
        self.assertIn("noble, resolute, stonking", summary)

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

    def test_summary_links_failed_source_evidence(self):
        result = {
            "base_version": "1-1",
            "series": ["noble"],
            "results": {
                "noble": {
                    "status": "failed",
                    "detail": "Launchpad source publication is Deleted",
                    "source_url": "https://launchpad.net/sourcepub/9",
                }
            },
        }
        summary = vp.render_summary(result)
        self.assertIn("https://launchpad.net/sourcepub/9", summary)


class PublicationDecisionTests(unittest.TestCase):
    def build(self, state, hours_ago=1.0, **kwargs):
        kwargs.setdefault("url", "https://launchpad.net/build/1")
        kwargs.setdefault("series", "noble")
        return vp.BuildEvidence(
            state=state,
            created=NOW - timedelta(hours=hours_ago),
            **kwargs,
        )

    def source(self, status="Pending", hours_ago=2.0, builds=()):
        return vp.SourceEvidence(
            version="1-1~ubuntu24.04.1",
            status=status,
            created=NOW - timedelta(hours=hours_ago),
            url="https://launchpad.net/sourcepub/1",
            builds=tuple(builds),
        )

    def classify(self, source=None, builds=(), **kwargs):
        return vp.classify_publication(
            series="noble",
            base_version="1-1",
            source=source,
            builds=builds,
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

    def test_deleted_source_publication_is_a_failure(self):
        deleted = self.source(status="Deleted", builds=())
        result = self.classify(source=deleted)
        self.assertEqual(result["status"], "failed")
        self.assertIn("Deleted", result["detail"])
        self.assertEqual(result["source_url"], "https://launchpad.net/sourcepub/1")

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

    def test_pending_source_without_a_build_is_pending_then_stale(self):
        fresh = self.classify(source=self.source(hours_ago=1.0))
        self.assertEqual(fresh["status"], "pending")
        self.assertIn("no build record", fresh["detail"])
        old = self.classify(source=self.source(hours_ago=30.0))
        self.assertEqual(old["status"], "stale")

    def test_published_source_without_packages_is_pending(self):
        published = self.source(status="Published", hours_ago=1.0)
        result = self.classify(source=published)
        self.assertEqual(result["status"], "pending")
        self.assertIn("Packages index", result["detail"])

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
            now=NOW,
            max_pending_hours=0,
        )
        self.assertEqual(result["status"], "pending")

    def test_unknown_build_state_is_rejected(self):
        new_state = self.build("Some new Launchpad state", 1.0)
        result = self.classify(source=self.source(builds=(new_state,)))
        self.assertEqual(result["status"], "failed")
        self.assertIn("unrecognised", result["detail"])

    def test_missing_upload_uses_the_pin_age(self):
        recent = self.classify(pin_committed=NOW - timedelta(hours=1))
        self.assertEqual(recent["status"], "pending")
        self.assertIn("no Launchpad source upload", recent["detail"])
        old = self.classify(pin_committed=NOW - timedelta(hours=30))
        self.assertEqual(old["status"], "stale")
        self.assertIn("no Launchpad source upload", old["detail"])

    def test_missing_upload_without_a_pin_stays_pending(self):
        result = self.classify()
        self.assertEqual(result["status"], "pending")

    def test_targets_are_explicit_and_ordered(self):
        self.assertEqual(
            list(vp.KNOWN_SERIES), ["noble", "resolute", "stonking"]
        )
        self.assertEqual(vp.SERIES, ("noble", "resolute", "stonking"))


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
    def __init__(self, version, status, builds, url="https://launchpad.net/sourcepub/1"):
        self.source_package_version = version
        self.status = status
        self.date_created = NOW - timedelta(hours=2)
        self.date_made_pending = None
        self.date_published = NOW - timedelta(hours=1)
        self.web_link = url
        self._builds = builds

    def getBuilds(self):
        return self._builds


class FakeArchive:
    def __init__(self, sources=None, builds=()):
        self.sources = sources or {}
        self.builds = builds
        self.status_queries: list[str] = []

    def getPublishedSources(self, *, status=None, **kwargs):
        self.status_queries.append(status)
        return self.sources.get(status, [])

    def getBuildRecords(self, **kwargs):
        return self.builds


class FakeLaunchpad:
    def __init__(self, archive):
        self.archive = archive

    def load(self, path):
        if path == vp.ARCHIVE:
            return self.archive
        return object()


class LaunchpadContextTests(unittest.TestCase):
    def context(self, sources=None, builds=()):
        archive = FakeArchive(sources, builds)
        return vp.LaunchpadContext(FakeLaunchpad(archive), 1)

    def test_targets_are_explicit_not_discovered(self):
        self.assertEqual(
            self.context().discover_series(),
            ["noble", "resolute", "stonking"],
        )

    def test_context_reads_source_and_build_records_without_recipe(self):
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
        context = self.context({"Published": [source]}, [archive_build])
        found = context.source_for("noble", "1-1")
        self.assertIsNotNone(found)
        self.assertEqual(found.status, "Published")
        self.assertEqual(len(found.builds), 1)
        builds = context.builds_for("noble", "1-1")
        self.assertEqual(len(builds), 1)
        self.assertEqual(builds[0].url, "https://launchpad.net/build/2")

    def test_pending_source_upload_is_found(self):
        pending = FakeSource("1-1~ubuntu24.04.1", "Pending", [])
        context = self.context({"Pending": [pending]})
        found = context.source_for("noble", "1-1")
        self.assertIsNotNone(found)
        self.assertEqual(found.status, "Pending")

    def test_deleted_source_is_exposed_for_a_failure(self):
        deleted = FakeSource("1-1~ubuntu24.04.1", "Deleted", [])
        context = self.context({"Deleted": [deleted]})
        found = context.source_for("noble", "1-1")
        self.assertIsNotNone(found)
        self.assertEqual(found.status, "Deleted")

    def test_context_ignores_other_versions(self):
        source = FakeSource("1-1~ubuntu24.04.1", "Published", [])
        context = self.context({"Published": [source]})
        self.assertIsNone(context.source_for("noble", "2-1"))
        self.assertEqual(context.builds_for("noble", "2-1"), [])

    def test_source_queries_are_status_scoped(self):
        archive = FakeArchive()
        context = vp.LaunchpadContext(FakeLaunchpad(archive), 1)
        self.assertIsNone(context.source_for("noble", "1-1"))
        self.assertEqual(
            archive.status_queries,
            ["Published", "Pending", "Deleted", "Obsolete"],
        )


class FakeContext:
    def __init__(self, series=("noble", "resolute", "stonking")):
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

    def test_result_records_the_explicit_target_set(self):
        result, written = self.run_with(
            {"status": "pending", "detail": "waiting"}
        )
        self.assertEqual(
            result["enabled_series"], ["noble", "resolute", "stonking"]
        )
        self.assertEqual(written["targets"], written["enabled_series"])
        self.assertNotIn("recipe", written)

    def test_pin_age_applies_when_verifying_the_pinned_version(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            args = self.run_args(tmp, "--base-version", "1.0-1")
            with mock.patch.object(
                vp, "git_commit_time", return_value=NOW
            ), mock.patch.object(
                vp, "collect_launchpad_context", return_value=FakeContext()
            ), mock.patch.object(
                vp, "verify_series",
                return_value={"status": "pending", "detail": "waiting"},
            ) as verify:
                vp.run(args)
        self.assertTrue(verify.call_args_list)
        for call in verify.call_args_list:
            self.assertEqual(call.args[8], NOW)

    def test_pin_age_does_not_apply_to_another_version(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            args = self.run_args(tmp, "--base-version", "9.9-1")
            with mock.patch.object(
                vp, "git_commit_time", return_value=NOW
            ), mock.patch.object(
                vp, "collect_launchpad_context", return_value=FakeContext()
            ), mock.patch.object(
                vp, "verify_series",
                return_value={"status": "pending", "detail": "waiting"},
            ) as verify:
                vp.run(args)
        self.assertTrue(verify.call_args_list)
        for call in verify.call_args_list:
            self.assertIsNone(call.args[8])

    def test_expect_series_must_match_the_target_set(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            args = self.run_args(
                Path(tmp_name), "--expect-series", "noble,resolute"
            )
            with mock.patch.object(
                vp, "collect_launchpad_context", return_value=FakeContext()
            ), mock.patch.object(vp, "verify_series", return_value={}):
                with self.assertRaises(vp.UsageError):
                    vp.run(args)

    def test_expect_series_accepts_the_full_target_set(self):
        result, _ = self.run_with(
            {"status": "pending", "detail": "waiting"},
            "--expect-series", "noble,resolute,stonking",
        )
        self.assertTrue(result["ok"])

    def test_unknown_selected_series_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            args = self.run_args(Path(tmp_name), "--series", "oracular")
            with mock.patch.object(
                vp, "collect_launchpad_context", return_value=FakeContext()
            ), mock.patch.object(vp, "verify_series", return_value={}):
                with self.assertRaises(vp.UsageError):
                    vp.run(args)


if __name__ == "__main__":
    unittest.main()
