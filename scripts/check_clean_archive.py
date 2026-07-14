#!/usr/bin/env python3
"""Fail loudly if a handoff archive contains environment/cache junk.

Handoff ZIPs have repeatedly shipped broken because they were zipped from a
working tree and carried ``.venv``, ``.git``, caches, ``__MACOSX``,
``.DS_Store``, ``__pycache__``, or ``*.pyc`` entries that shadow a clean
install and break ``uv run`` after extraction.

This is a guard, not a packaging tool: prefer building the archive from a clean
tree (``git archive --format=zip --output dist/ReentbotPro-clean.zip HEAD``)
and then run this checker over the result before sending it.

Usage:
    python scripts/check_clean_archive.py <archive.zip> [<archive.zip> ...]

Exits non-zero and lists offending entries when any forbidden path is present.
"""

from __future__ import annotations

import sys
import zipfile
from collections.abc import Iterable

# Path *components* (split on "/") that must never appear in a clean archive.
# Matching whole components keeps legitimate files like ``.gitignore`` or
# ``.gitattributes`` allowed while still rejecting the ``.git`` directory.
FORBIDDEN_COMPONENTS = frozenset(
    {
        ".git",
        ".venv",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "__pycache__",
        "__MACOSX",
    }
)

# Exact basenames that must never appear.
FORBIDDEN_BASENAMES = frozenset({".DS_Store"})

# Basename suffixes that must never appear (compiled Python).
FORBIDDEN_SUFFIXES = (".pyc", ".pyo")


def is_forbidden(name: str) -> bool:
    """Return True if a single archive entry name is forbidden."""
    parts = [p for p in name.replace("\\", "/").split("/") if p]
    if not parts:
        return False
    if any(part in FORBIDDEN_COMPONENTS for part in parts):
        return True
    basename = parts[-1]
    if basename in FORBIDDEN_BASENAMES:
        return True
    return basename.endswith(FORBIDDEN_SUFFIXES)


def find_forbidden_entries(names: Iterable[str]) -> list[str]:
    """Return the sorted, de-duplicated forbidden entries from ``names``."""
    return sorted({name for name in names if is_forbidden(name)})


def check_archive(path: str) -> list[str]:
    """Return the sorted forbidden entries inside the zip at ``path``."""
    with zipfile.ZipFile(path) as zf:
        return find_forbidden_entries(zf.namelist())


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("error: no archive path given", file=sys.stderr)
        return 2
    status = 0
    for path in argv:
        try:
            offenders = check_archive(path)
        except FileNotFoundError:
            print(f"{path}: error: file not found", file=sys.stderr)
            status = 2
            continue
        except zipfile.BadZipFile:
            print(f"{path}: error: not a valid zip archive", file=sys.stderr)
            status = 2
            continue
        if offenders:
            status = 1
            print(f"{path}: FAIL ({len(offenders)} forbidden entries)")
            for entry in offenders:
                print(f"  {entry}")
        else:
            print(f"{path}: OK")
    return status


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
