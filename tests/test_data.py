import unittest

from glyphguard import core, data


class TestDataTables(unittest.TestCase):
    def test_confusables_are_single_chars(self):
        for src, base in data.CONFUSABLES.items():
            self.assertEqual(len(src), 1, src)
            self.assertTrue(base.isprintable(), base)

    def test_confusables_target_is_ascii(self):
        for src, base in data.CONFUSABLES.items():
            self.assertTrue(base.isascii(), (src, base))

    def test_algorithmic_ranges_are_solid(self):
        for start, end, offset in data.ALGORITHMIC_CONFUSABLES:
            for cp in (start, (start + end) // 2, end):
                base = chr(cp + offset)
                self.assertTrue(base.isascii(), (hex(cp), base))
                self.assertTrue(0x21 <= ord(base) <= 0x7E, (hex(cp), base))
                # Fullwidth forms legitimately map to ASCII punctuation; every
                # other range must map to an ASCII letter or digit (guards
                # against offset errors that would land on symbols like "@").
                if not (0xFF01 <= cp <= 0xFF5E):
                    self.assertTrue(base.isalnum(), (hex(cp), base))

    def test_fullwidth_mapping(self):
        # FF41 -> 'a'
        self.assertEqual(core.algorithmic_base("\uff41"), "a")
        self.assertEqual(core.algorithmic_base("\uff21"), "A")

    def test_math_bold_mapping(self):
        # MATHEMATICAL BOLD SMALL A = U+1D41A -> 'a'
        self.assertEqual(core.algorithmic_base("\U0001d41a"), "a")

    def test_text_extensions_nonempty(self):
        self.assertIn(".py", data.TEXT_EXTENSIONS)
        self.assertIn(".go", data.TEXT_EXTENSIONS)


if __name__ == "__main__":
    unittest.main()
