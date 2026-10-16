import unittest

from glyphguard import detect


class TestInvisibles(unittest.TestCase):
    def test_zero_width_flagged(self):
        findings = detect.find_invisibles("a\u200bb")
        self.assertTrue(any(f.kind == "invisible" for f in findings))

    def test_bidi_critical(self):
        findings = detect.find_invisibles("x\u202ey")  # RLO
        bidi = [f for f in findings if f.kind == "bidi"]
        self.assertTrue(bidi)
        self.assertEqual(bidi[0].severity, "critical")


class TestControl(unittest.TestCase):
    def test_nul_critical(self):
        findings = detect.find_control("a\x00b")
        self.assertTrue(any(f.severity == "critical" for f in findings))

    def test_tab_allowed(self):
        findings = detect.find_control("a\tb")
        self.assertFalse(findings)


class TestConfusables(unittest.TestCase):
    def test_cyrillic_word(self):
        findings = detect.find_confusables("аррle")
        conf = [f for f in findings if f.kind == "confusable"]
        self.assertTrue(conf)
        self.assertTrue(all(f.severity == "critical" for f in conf))

    def test_plain_ascii_clean(self):
        findings = detect.find_confusables("apple")
        self.assertFalse(any(f.kind == "confusable" for f in findings))


class TestMixedScripts(unittest.TestCase):
    def test_cyrillic_latin_mix(self):
        findings = detect.find_mixed_scripts("аррle")
        self.assertTrue(any(f.kind == "mixed-script" for f in findings))

    def test_cjk_latin_ok(self):
        findings = detect.find_mixed_scripts("变量name")
        self.assertFalse(any(f.kind == "mixed-script" for f in findings))


class TestNonNormalized(unittest.TestCase):
    def test_decomposed(self):
        findings = detect.find_non_normalized("e\u0301")
        self.assertTrue(any(f.kind == "non-normalized" for f in findings))


class TestDomain(unittest.TestCase):
    def test_homograph(self):
        skeleton, findings = detect.check_domain("аррle.com")
        self.assertEqual(skeleton, "apple.com")
        self.assertTrue(findings)

    def test_plain_domain(self):
        skeleton, findings = detect.check_domain("example.com")
        self.assertEqual(skeleton, "example.com")
        self.assertFalse(findings)


if __name__ == "__main__":
    unittest.main()
