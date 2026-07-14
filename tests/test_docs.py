"""Stable-doc contracts.

These pin two things that silently rot otherwise:

1. ``AGENTS.md`` and ``CLAUDE.md`` are the same guide and must stay
   byte-identical, so the two never drift apart.
2. The clean-archive checker actually rejects the environment/cache junk that
   has repeatedly broken handoff ZIPs, and passes a clean source archive.
"""

import importlib.util
import io
import os
import unittest
import zipfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_checker():
    path = os.path.join(_REPO_ROOT, "scripts", "check_clean_archive.py")
    spec = importlib.util.spec_from_file_location("check_clean_archive", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _zip_bytes(names):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name in names:
            zf.writestr(name, "x")
    buffer.seek(0)
    return buffer.read()


class AgentsClaudeEqualityTests(unittest.TestCase):
    def test_agents_and_claude_docs_are_identical(self):
        agents = os.path.join(_REPO_ROOT, "AGENTS.md")
        claude = os.path.join(_REPO_ROOT, "CLAUDE.md")
        with open(agents, "rb") as fh:
            agents_bytes = fh.read()
        with open(claude, "rb") as fh:
            claude_bytes = fh.read()
        self.assertEqual(
            agents_bytes,
            claude_bytes,
            "AGENTS.md and CLAUDE.md must stay byte-identical; edit both together.",
        )


class CleanArchiveCheckerTests(unittest.TestCase):
    def setUp(self):
        self.checker = _load_checker()

    def test_is_forbidden_flags_junk_keeps_real_files(self):
        forbidden = [
            ".git/config",
            ".venv/bin/python",
            "pkg/__pycache__/mod.cpython-311.pyc",
            "src/reentbotpro/mod.pyc",
            "__MACOSX/foo",
            "project/.DS_Store",
            ".pytest_cache/v/cache",
            ".ruff_cache/x",
        ]
        for name in forbidden:
            self.assertTrue(self.checker.is_forbidden(name), name)

        allowed = [
            "src/reentbotpro/agent.py",
            ".gitignore",
            ".gitattributes",
            "README.md",
            "tests/test_docs.py",
            "docs/attack-campaign-engine.md",
        ]
        for name in allowed:
            self.assertFalse(self.checker.is_forbidden(name), name)

    def test_find_forbidden_entries_is_sorted_and_deduped(self):
        names = [".venv/a", ".venv/a", "src/x.py", "b.pyc", "a.pyc"]
        self.assertEqual(
            self.checker.find_forbidden_entries(names),
            [".venv/a", "a.pyc", "b.pyc"],
        )

    def test_check_archive_passes_clean_zip(self):
        data = _zip_bytes(["README.md", "src/reentbotpro/agent.py", ".gitignore"])
        with self._temp_zip(data) as path:
            self.assertEqual(self.checker.check_archive(path), [])

    def test_check_archive_fails_dirty_zip(self):
        data = _zip_bytes(
            [
                "README.md",
                ".venv/bin/python",
                "pkg/__pycache__/m.pyc",
                "project/.DS_Store",
            ]
        )
        with self._temp_zip(data) as path:
            offenders = self.checker.check_archive(path)
        self.assertIn(".venv/bin/python", offenders)
        self.assertIn("pkg/__pycache__/m.pyc", offenders)
        self.assertIn("project/.DS_Store", offenders)
        self.assertNotIn("README.md", offenders)

    def test_main_returns_nonzero_for_dirty_and_zero_for_clean(self):
        dirty = _zip_bytes(["app.py", ".venv/bin/python"])
        clean = _zip_bytes(["app.py", "README.md"])
        with self._temp_zip(dirty) as dirty_path:
            self.assertEqual(self.checker.main([dirty_path]), 1)
        with self._temp_zip(clean) as clean_path:
            self.assertEqual(self.checker.main([clean_path]), 0)

    def test_main_with_no_args_is_usage_error(self):
        self.assertEqual(self.checker.main([]), 2)

    def _temp_zip(self, data):
        import contextlib
        import tempfile

        @contextlib.contextmanager
        def _ctx():
            fd, path = tempfile.mkstemp(suffix=".zip")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                yield path
            finally:
                os.unlink(path)

        return _ctx()


if __name__ == "__main__":
    unittest.main()
