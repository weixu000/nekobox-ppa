"""Tests for scripts/prepare-update.py.

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare-update.py"


def load_module():
    spec = importlib.util.spec_from_file_location("prepare_update", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


pu = load_module()


ENV_TEXT = """# pinned release
UPSTREAM_VERSION=5.11.28.3
UPSTREAM_TARBALL=nekobox-unified-source-5.11.28.3.tar.xz
UPSTREAM_URL=https://github.com/qr243vbi/nekobox/releases/download/5.11.28.3/nekobox-unified-source-5.11.28.3.tar.xz
UPSTREAM_SHA256=aaaa
UPSTREAM_TOP_DIR=nekobox-unified-source-5.11.28.3
UPSTREAM_SOURCE_DATE_EPOCH=1787770472
DEBIAN_REVISION=2~ppa1
DEBIAN_DISTRIBUTION=resolute
"""

RECIPE_TEXT = """# git-build-recipe format 0.4 deb-version 5.11.28.3-2~ppa1
#
# pinned 5.11.28.3 for testing
lp:~oblivionw26/+git/nekobox-ppa upstream/5.11.28.3
nest-part packaging lp:~oblivionw26/+git/nekobox-ppa debian debian main
"""


class PrepareUpdateTests(unittest.TestCase):
    def test_env_update_preserves_comments_and_replaces_once(self):
        values = {
            "UPSTREAM_VERSION": "5.11.28.4",
            "UPSTREAM_TARBALL": "nekobox-unified-source-5.11.28.4.tar.xz",
            "UPSTREAM_URL": "https://example.invalid/x.tar.xz",
            "UPSTREAM_SHA256": "b" * 64,
            "UPSTREAM_TOP_DIR": "nekobox-unified-source-5.11.28.4",
            "UPSTREAM_SOURCE_DATE_EPOCH": "123",
        }
        updated = pu.update_env_text(ENV_TEXT, values)
        self.assertIn("# pinned release", updated)
        for key, value in values.items():
            self.assertIn(f"{key}={value}", updated)
        self.assertIn("DEBIAN_REVISION=2~ppa1", updated)

    def test_recipe_update_changes_header_and_branch(self):
        updated = pu.update_recipe_text(
            RECIPE_TEXT, "5.11.28.3", "5.11.28.4", "2~ppa1"
        )
        self.assertTrue(
            updated.startswith(
                "# git-build-recipe format 0.4 deb-version 5.11.28.4-2~ppa1"
            )
        )
        self.assertIn("upstream/5.11.28.4", updated)
        self.assertNotIn("5.11.28.3", updated)

    def test_changelog_prepend_and_version(self):
        old = "nekobox (5.11.28.3-2~ppa1) resolute; urgency=medium\n\n -- X <x@y>  date\n"
        new = pu.prepend_changelog(
            old,
            "5.11.28.4-2~ppa1",
            "resolute",
            "  * New upstream stable release 5.11.28.4.",
            "Mon, 23 Nov 2026 00:00:00 +0000",
        )
        self.assertEqual(pu.changelog_version(new), "5.11.28.4-2~ppa1")
        self.assertTrue(new.endswith(old))

    def test_archive_top_dir_rejects_unsafe_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.tar.xz"
            with tarfile.open(path, "w:xz") as archive:
                data = b"x"
                info = tarfile.TarInfo("../escape")
                info.size = 1
                archive.addfile(info, io.BytesIO(data))
            with self.assertRaises(pu.VerificationError):
                pu.archive_top_dir(path)

    def test_archive_top_dir_rejects_escaping_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.tar.xz"
            with tarfile.open(path, "w:xz") as archive:
                info = tarfile.TarInfo("top/link")
                info.type = tarfile.SYMTYPE
                info.linkname = "../../etc/passwd"
                archive.addfile(info)
            with self.assertRaises(pu.VerificationError):
                pu.archive_top_dir(path)

    def test_archive_top_dir_requires_one_top_level(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.tar.xz"
            with tarfile.open(path, "w:xz") as archive:
                for name in ("a/file", "b/file"):
                    info = tarfile.TarInfo(name)
                    info.size = 1
                    archive.addfile(info, io.BytesIO(b"x"))
            with self.assertRaises(pu.VerificationError):
                pu.archive_top_dir(path)

    def test_cli_updates_metadata_from_verified_tarball(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "debian").mkdir()
            (repo / "downloads").mkdir()
            (repo / "upstream.env").write_text(ENV_TEXT, encoding="utf-8")
            (repo / "nekobox.recipe").write_text(RECIPE_TEXT, encoding="utf-8")
            (repo / "debian" / "changelog").write_text(
                "nekobox (5.11.28.3-2~ppa1) resolute; urgency=medium\n\n"
                " -- Oblivion W <oblivion.w23@gmail.com>  Fri, 20 Nov 2026 20:56:07 +0800\n",
                encoding="utf-8",
            )

            tarball = repo / "downloads" / "nekobox-unified-source-5.11.28.4.tar.xz"
            with tarfile.open(tarball, "w:xz") as archive:
                payload = b"hello\n"
                info = tarfile.TarInfo(
                    "nekobox-unified-source-5.11.28.4/README"
                )
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            digest = hashlib.sha256(tarball.read_bytes()).hexdigest()

            check = {
                "schema_version": 1,
                "status": "update-available",
                "current": {"version": "5.11.28.3"},
                "candidate": {
                    "version": "5.11.28.4",
                    "asset_name": "nekobox-unified-source-5.11.28.4.tar.xz",
                    "asset_url": (
                        "https://github.com/qr243vbi/nekobox/releases/download/"
                        "5.11.28.4/nekobox-unified-source-5.11.28.4.tar.xz"
                    ),
                    "digest": "sha256:" + digest,
                    "size": tarball.stat().st_size,
                    "released_at": "2026-09-01T00:00:00Z",
                },
            }
            check_path = repo / "check.json"
            check_path.write_text(json.dumps(check), encoding="utf-8")
            metadata_path = repo / "build" / "release.json"

            rc = pu.main(
                [
                    "--check-json",
                    str(check_path),
                    "--repo-root",
                    str(repo),
                    "--tarball",
                    str(tarball),
                    "--metadata",
                    str(metadata_path),
                ]
            )
            self.assertEqual(rc, 0)
            metadata = json.loads(metadata_path.read_text())
            self.assertEqual(metadata["version"], "5.11.28.4")
            self.assertEqual(metadata["base_version"], "5.11.28.4-2~ppa1")
            self.assertEqual(metadata["sha256"], digest)
            env = (repo / "upstream.env").read_text()
            self.assertIn("UPSTREAM_VERSION=5.11.28.4", env)
            self.assertIn(f"UPSTREAM_SHA256={digest}", env)
            changelog = (repo / "debian" / "changelog").read_text()
            self.assertTrue(
                changelog.startswith("nekobox (5.11.28.4-2~ppa1) resolute;")
            )
            recipe = (repo / "nekobox.recipe").read_text()
            self.assertIn("upstream/5.11.28.4", recipe)


if __name__ == "__main__":
    unittest.main()
