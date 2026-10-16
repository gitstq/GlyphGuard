import os
import tempfile
import unittest

from glyphguard import audit


class TestAuditText(unittest.TestCase):
    def test_clean(self):
        rep = audit.audit_text("hello world")
        self.assertEqual(rep.score, 100)
        self.assertEqual(len(rep.findings), 0)
        self.assertEqual(rep.exit_code(), 0)

    def test_trojan_source(self):
        rep = audit.audit_text('x = 1  # \u202e injected')
        self.assertTrue(rep.critical > 0)
        self.assertEqual(rep.exit_code("critical"), 2)

    def test_stats(self):
        rep = audit.audit_text("变量 \u4e2d")
        self.assertEqual(rep.stats["non_ascii"], 3)


class TestAuditFile(unittest.TestCase):
    def test_file_with_invisible(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("a\u200bb\n")
            path = fh.name
        try:
            rep = audit.audit_file(path)
            self.assertTrue(any(f.kind == "invisible" for f in rep.findings))
        finally:
            os.unlink(path)

    def test_missing_file(self):
        rep = audit.audit_file("/no/such/file.py")
        self.assertEqual(rep.score, 100)


class TestAuditPath(unittest.TestCase):
    def test_recursive(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.txt"), "w", encoding="utf-8") as fh:
                fh.write("clean\n")
            with open(os.path.join(d, "b.py"), "w", encoding="utf-8") as fh:
                fh.write("x\u202ey\n")
            reports = audit.audit_path(d, recursive=True)
            self.assertIn(os.path.join(d, "b.py"), reports)
            self.assertNotIn(os.path.join(d, "a.txt"), reports)


if __name__ == "__main__":
    unittest.main()
