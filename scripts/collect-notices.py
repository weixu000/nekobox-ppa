#!/usr/bin/env python3
"""Collect the licence and notice material shipped by the NekoBox build.

The script reads an extracted upstream source tree (the one made by
scripts/prepare-source.sh) and writes a deterministic copy of the licence
files that belong to third-party code compiled into the binary package:

  generated/go/<module>/...        licence files of every module in
                                   core/server/vendor/modules.txt
  generated/cpp/<component>/...    licence files shipped for a bundled
                                   C/C++ component
  generated/inline/<component>/... leading copyright/licence comment of a
                                   bundled file that has no separate licence
                                   file (the exact comment text is copied)
  INDEX.txt                        installed path, source path and sha256 of
                                   every copied file

The hand-maintained upstream/ directory holds licence texts that the
upstream tarball does not ship; those files are indexed as well.  It is
never modified by this script.  See upstream/PROVENANCE.txt.

Only the C/C++ components that this packaging actually compiles are listed
in CPP_LICENCE_FILES and INLINE_NOTICE_FILES.  The Go set is the vendor set
from modules.txt; it is a superset of the modules linked into the amd64 core
(for example Windows-only modules are vendored too), which is why the copied
set is safe to regenerate from the source tree alone.

Usage:
    scripts/collect-notices.py --source build/nekobox-5.11.28.3
    scripts/collect-notices.py --source /tmp/nekobox-5.11.28.3 --check

--check compares the result with the files already in debian/third-party and
exits non-zero on any difference (no writes).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import sys
from pathlib import Path

# Directories whose contents are never part of the licence inventory.
SKIP_DIRS = {".git", "testdata"}

LICENCE_NAME = re.compile(
    r"^(LICEN[CS]E|COPYING|COPYRIGHT|NOTICE|UNLICENSE)(\.[A-Za-z0-9.+-]+)?$",
    re.IGNORECASE,
)

# C/C++ components that ship a licence file and are compiled into the GUI.
# cpr/test/LICENSE belongs to the test suite and is deliberately not copied.
CPP_LICENCE_FILES = [
    ("cpr", "src/3rdparty/cpr/LICENSE"),
    ("qjs", "src/3rdparty/qjs/LICENSE"),
]

# Files scanned for an inline copyright/licence comment, with the component
# directory used in the output.  Every path here is compiled into the GUI
# (see CMakeLists.txt and the build flags), or is a theme/image resource
# embedded in it.
INLINE_NOTICE_FILES = [
    # quirc: ISC-style notice at the top of every source file.
    ("quirc", "src/3rdparty/quirc/lib/decode.c"),
    ("quirc", "src/3rdparty/quirc/lib/identify.c"),
    ("quirc", "src/3rdparty/quirc/lib/quirc.c"),
    ("quirc", "src/3rdparty/quirc/lib/quirc_internal.h"),
    ("quirc", "src/3rdparty/quirc/lib/quirc.h"),
    ("quirc", "src/3rdparty/quirc/lib/version_db.c"),
    # qrcodegen: MIT notice at the top of both files.
    ("qrcodegen", "src/3rdparty/qrcodegen/qrcodegen.cpp"),
    ("qrcodegen", "src/3rdparty/qrcodegen/qrcodegen.hpp"),
    # LRUCache: ISC-style notice.
    ("LRUCache", "src/3rdparty/LRUCache/LRUCache11.hpp"),
    # Qv2ray files compiled into the GUI.  QvProxyConfigurator.cpp is not
    # listed: USE_CPP_PROXY_CONFIGURATOR is not defined, so its body is
    # compiled out and it contributes no code.
    ("qv2ray", "src/3rdparty/qv2ray/v2/ui/LogHighlighter.cpp"),
    ("qv2ray", "src/3rdparty/qv2ray/v2/ui/LogHighlighter.hpp"),
    ("qv2ray", "src/3rdparty/qv2ray/v2/ui/QvAutoCompleteTextEdit.cpp"),
    ("qv2ray", "src/3rdparty/qv2ray/v2/ui/QvAutoCompleteTextEdit.hpp"),
    ("qv2ray", "src/3rdparty/qv2ray/v2/ui/widgets/common/QJsonModel.cpp"),
    ("qv2ray", "src/3rdparty/qv2ray/v2/ui/widgets/common/QJsonModel.hpp"),
    ("qv2ray", "src/3rdparty/qv2ray/v2/ui/widgets/editors/w_JsonEditor.cpp"),
    ("qv2ray", "src/3rdparty/qv2ray/v2/ui/widgets/editors/w_JsonEditor.hpp"),
    ("qv2ray", "src/3rdparty/qv2ray/v2/ui/widgets/speedchart/SpeedWidget.cpp"),
    ("qv2ray", "src/3rdparty/qv2ray/v2/ui/widgets/speedchart/SpeedWidget.hpp"),
    # Theme files embedded through res/darkstyle.qrc and
    # res/qss/feiyangqingyun/qss.qrc.  Only comments actually present are
    # copied; several of these files have no notice at all.
    ("qss", "res/qss/AMOLED.qss"),
    ("qss", "res/qss/Aqua.qss"),
    ("qss", "res/qss/Kawaii.qss"),
    ("qss", "res/qss/MaterialDark.qss"),
    ("qss", "res/qss/feiyangqingyun/qss/blacksoft.qss"),
    ("qss", "res/qss/feiyangqingyun/qss/flatgray.qss"),
    ("qss", "res/qss/feiyangqingyun/qss/lightblue.qss"),
    # First-party file that contains an attributed snippet:
    # "launchatlogin.cpp / ShadowClash / Copyright (c) 2019 Coel Wu" and a
    # reference to nextcloud/desktop.  The notice is preserved verbatim;
    # debian/copyright records that the snippet's licence is unresolved.
    ("nekobox", "src/gharqad/sys/AutoRun.cpp"),
]

NOTICE_KEYWORDS = (
    "copyright",
    "license",
    "licence",
    "permission",
    "redistribution",
    "spdx",
    "all rights reserved",
)

QSS_EXTRA_KEYWORDS = (
    "author",
    "available at",
    "stylesheet",
    "style sheet",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_modules(modules_txt: Path) -> list[tuple[str, str]]:
    """Return (module path, version) pairs from vendor/modules.txt.

    Replacement-only lines ("# old => new vX") are included under the old
    path because that is the directory name in vendor/.  Duplicate paths are
    collapsed deterministically.
    """
    modules: dict[str, str] = {}
    line_re = re.compile(r"^# (\S+)(?: (\S+))?(?: => \S+ \S+)?$")
    for line in modules_txt.read_text(encoding="utf-8").splitlines():
        if not line.startswith("# "):
            continue
        match = line_re.match(line)
        if not match:
            continue
        module = match.group(1)
        version = match.group(2) or ""
        modules[module] = version
    return sorted(modules.items())


def walk_licence_files(root: Path):
    """Yield licence-like files below root, in a stable order."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if LICENCE_NAME.match(name):
                yield Path(dirpath) / name


def leading_notice(text: str, qss: bool) -> str | None:
    """Return the first comment block in the first 200 lines that looks like
    a copyright/licence notice, verbatim.  None if there is no such block."""
    max_offset = len("\n".join(text.splitlines()[:200]))
    blocks: list[tuple[int, str]] = []

    for match in re.finditer(r"/\*.*?\*/", text, re.DOTALL):
        if match.start() <= max_offset:
            blocks.append((match.start(), match.group(0)))
    if not qss:
        for match in re.finditer(r"(?m)(?:^[ \t]*//[^\n]*(?:\n|$))+", text):
            if match.start() <= max_offset:
                blocks.append((match.start(), match.group(0).rstrip("\n")))

    blocks.sort(key=lambda item: item[0])
    for _, block in blocks:
        lowered = block.lower()
        if any(word in lowered for word in NOTICE_KEYWORDS):
            return block.rstrip("\n") + "\n"
        if qss and any(word in lowered for word in QSS_EXTRA_KEYWORDS):
            return block.rstrip("\n") + "\n"
    return None


class Collector:
    def __init__(self, source: Path, output: Path):
        self.source = source
        self.output = output
        self.generated = output / "generated"
        self.entries: list[tuple[str, str, str]] = []

    def license_file(self, dest_rel: str, src_rel: str) -> None:
        src = self.source / src_rel
        if not src.is_file():
            sys.exit(f"error: missing licence file in source: {src_rel}")
        dest = self.generated / dest_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        os.chmod(dest, 0o644)
        self.entries.append((f"generated/{dest_rel}", src_rel, sha256_file(src)))

    def inline_notice(self, dest_rel: str, src_rel: str) -> None:
        src = self.source / src_rel
        if not src.is_file():
            sys.exit(f"error: missing notice source in source tree: {src_rel}")
        text = src.read_text(encoding="utf-8", errors="replace")
        notice = leading_notice(text, src_rel.endswith(".qss"))
        if notice is None:
            return
        dest = self.generated / dest_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(notice, encoding="utf-8")
        os.chmod(dest, 0o644)
        self.entries.append((f"generated/{dest_rel}", src_rel, sha256_file(dest)))

    def collect_go(self) -> int:
        modules_txt = self.source / "core/server/vendor/modules.txt"
        if not modules_txt.is_file():
            sys.exit(f"error: not a NekoBox source tree: {modules_txt} missing")
        modules = parse_modules(modules_txt)
        vendor = self.source / "core/server/vendor"
        for module, _version in modules:
            module_dir = vendor / module
            if not module_dir.is_dir():
                sys.exit(f"error: vendored module directory missing: {module}")
            files = list(walk_licence_files(module_dir))
            if not files:
                sys.exit(f"error: no licence file found for module {module}")
            for path in files:
                rel = path.relative_to(module_dir).as_posix()
                self.license_file(f"go/{module}/{rel}", path.relative_to(self.source).as_posix())
        return len(modules)

    def collect_cpp(self) -> None:
        for component, relpath in CPP_LICENCE_FILES:
            self.license_file(f"cpp/{component}/{Path(relpath).name}", relpath)
        for component, relpath in INLINE_NOTICE_FILES:
            dest = f"inline/{component}/{relpath}.txt"
            self.inline_notice(dest, relpath)

    def collect_upstream(self) -> None:
        upstream = self.output / "upstream"
        if not upstream.is_dir():
            return
        for path in sorted(p for p in upstream.rglob("*") if p.is_file()):
            if not LICENCE_NAME.match(path.name):
                continue
            rel = path.relative_to(self.output).as_posix()
            self.entries.append((rel, f"debian/third-party/{rel}", sha256_file(path)))

    def run(self) -> None:
        if not (self.source / "src/3rdparty").is_dir():
            sys.exit(f"error: {self.source} does not look like extracted NekoBox source")
        if self.generated.exists():
            shutil.rmtree(self.generated)
        self.generated.mkdir(parents=True)
        module_count = self.collect_go()
        self.collect_cpp()
        self.collect_upstream()
        # A vendored module can live below another vendored module (for
        # example github.com/sagernet/cronet-go/lib/android_386).  Both walks
        # then find the same file and derive the same destination; keep one
        # entry, but refuse to hide a genuine content conflict.
        unique: dict[str, tuple[str, str]] = {}
        for dest, src, digest in self.entries:
            if dest in unique:
                if unique[dest][1] != digest:
                    sys.exit(f"error: conflicting copies for {dest}")
                continue
            unique[dest] = (src, digest)
        self.entries = [(dest, src, digest) for dest, (src, digest) in unique.items()]
        self.entries.sort(key=lambda item: item[0])
        lines = [
            "# Licence and notice inventory for the nekobox binary package.",
            "# Generated by scripts/collect-notices.py; do not edit.",
            "# Installed paths are relative to /usr/share/doc/nekobox/third-party/.",
            "# Source paths are relative to the extracted upstream source root,",
            "# except upstream/ entries, whose source path is the packaging path.",
            "# vendored Go modules: %d (core/server/vendor/modules.txt)" % module_count,
            "#",
        ]
        lines.extend(f"{dest}\t{src}\t{digest}" for dest, src, digest in self.entries)
        (self.output / "INDEX.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--source",
        required=True,
        type=Path,
        help="extracted upstream source tree (contains core/server/vendor)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "debian/third-party",
        help="inventory directory (default: debian/third-party)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="only compare with the existing inventory; write nothing",
    )
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    collector = Collector(source, output)
    if args.check:
        # Build the expected set in a temporary directory next to the real
        # one, then compare it with the checked-in files.
        import tempfile

        with tempfile.TemporaryDirectory(prefix="nekobox-notices-") as tmp:
            tmp_output = Path(tmp) / "third-party"
            # Only the upstream/ evidence files need to be visible.
            if (output / "upstream").is_dir():
                shutil.copytree(output / "upstream", tmp_output / "upstream")
            tmp_collector = Collector(source, tmp_output)
            tmp_collector.run()
            problems = []
            for dest, src, digest in tmp_collector.entries:
                real = output / dest
                if not real.is_file():
                    problems.append(f"missing: {dest}")
                elif sha256_file(real) != digest:
                    problems.append(f"changed: {dest}")
            expected = {dest for dest, _, _ in tmp_collector.entries}
            if (output / "generated").is_dir():
                for path in (output / "generated").rglob("*"):
                    if path.is_file():
                        rel = path.relative_to(output).as_posix()
                        if rel not in expected:
                            problems.append(f"stale:   {rel}")
            index = output / "INDEX.txt"
            if not index.is_file():
                problems.append("missing: INDEX.txt")
            elif index.read_bytes() != (tmp_output / "INDEX.txt").read_bytes():
                problems.append("INDEX.txt differs")
            if problems:
                for problem in problems:
                    print(problem, file=sys.stderr)
                return 1
            print(f"up to date: {len(expected)} files")
            return 0

    collector.run()
    print(
        "wrote %d entries to %s"
        % (len(collector.entries), (output / "INDEX.txt"))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
