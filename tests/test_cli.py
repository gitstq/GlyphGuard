import contextlib
import io
import os
import tempfile
import unittest

from glyphguard.cli import main
from glyphguard.__init__ import __version__


class TestCli(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        code = None
        try:
            with contextlib.redirect_stdout(buf):
                code = main(argv)
        except SystemExit as exc:
            code = exc.code
        return code, buf.getvalue()

    def test_version(self):
        code, out = self._run(["version"])
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)

    def test_skeleton(self):
        code, out = self._run(["skeleton", "\u0430\u0440\u0440le"])
        self.assertEqual(code, 0)
        self.assertIn("apple", out)

    def test_width(self):
        code, out = self._run(["width", "\u4e2d"])
        self.assertEqual(code, 0)
        self.assertIn("Width: 2", out)

    def test_inspect(self):
        code, out = self._run(["inspect", "a\u200b"])
        self.assertEqual(code, 0)
        self.assertIn("U+200B", out)

    def test_normalize(self):
        code, out = self._run(["normalize", "e\u0301"])
        self.assertEqual(code, 0)
        self.assertIn("\u00e9", out)

    def test_domain(self):
        code, out = self._run(["domain", "\u0430\u0440\u0440le.com"])
        self.assertEqual(code, 2)
        self.assertIn("apple.com", out)

    def test_audit_clean(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("clean text\n")
            path = fh.name
        try:
            code, out = self._run(["audit", path, "--no-color"])
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)

    def test_audit_trojan(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("x = 1  # \u202e evil\n")
            path = fh.name
        try:
            code, out = self._run(["audit", path, "--no-color"])
            self.assertEqual(code, 2)
        finally:
            os.unlink(path)

    def test_audit_json(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("x\u202ey\n")
            path = fh.name
        try:
            code, out = self._run(["audit", path, "--format", "json"])
            self.assertEqual(code, 2)
            self.assertIn('"critical"', out)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
