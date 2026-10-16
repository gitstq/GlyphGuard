import unittest

from glyphguard import core


class TestCharInfo(unittest.TestCase):
    def test_latin(self):
        info = core.char_info("a")
        self.assertEqual(info.codepoint, "U+0061")
        self.assertEqual(info.script, "Latin")
        self.assertEqual(info.category, "Ll")

    def test_cyrillic_script(self):
        self.assertEqual(core.script_of("\u0430"), "Cyrillic")
        self.assertEqual(core.script_of("а"), "Cyrillic")

    def test_han_script(self):
        self.assertEqual(core.script_of("中"), "Han")

    def test_fullwidth_script_inherits(self):
        # Fullwidth 'a' inherits Latin
        self.assertEqual(core.script_of("\uff41"), "Latin")

    def test_block(self):
        self.assertEqual(core.block_of("a"), "Basic Latin")
        self.assertEqual(core.block_of("中"), "CJK Unified Ideographs")


class TestWidth(unittest.TestCase):
    def test_ascii_width(self):
        self.assertEqual(core.display_width("abc"), 3)

    def test_cjk_width(self):
        self.assertEqual(core.char_width("中"), 2)

    def test_zero_width(self):
        self.assertEqual(core.char_width("\u200b"), 0)
        self.assertEqual(core.char_width("\u0301"), 0)

    def test_combining(self):
        self.assertTrue(core.is_zero_width("\u0301"))


class TestNormalize(unittest.TestCase):
    def test_nfc_nfd_roundtrip(self):
        composed = "é"
        decomposed = core.normalize_text(composed, "NFD")
        self.assertEqual(core.normalize_text(decomposed, "NFC"), composed)

    def test_clean_removes_zwsp(self):
        self.assertNotIn("\u200b", core.clean_text("a\u200bb"))

    def test_clean_removes_nul(self):
        self.assertNotIn("\x00", core.clean_text("a\x00b"))


class TestEscape(unittest.TestCase):
    def test_unicode_escape_roundtrip(self):
        text = "café \u4e2d\u200b"
        esc = core.escape_text(text, "unicode")
        self.assertIn("\\u200B", esc)
        self.assertEqual(core.unescape_text(esc), text)

    def test_html_escape(self):
        esc = core.escape_text("\u4e2d", "html")
        self.assertEqual(esc, "&#x4E2D;")
        self.assertEqual(core.unescape_text(esc), "\u4e2d")


class TestSkeleton(unittest.TestCase):
    def test_cyrillic_to_ascii(self):
        self.assertEqual(core.skeleton("\u0430\u0440\u0440le"), "apple")

    def test_fullwidth_skeleton(self):
        self.assertEqual(core.skeleton("\uff41\uff42"), "ab")


if __name__ == "__main__":
    unittest.main()
