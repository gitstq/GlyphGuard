"""Embedded Unicode security data tables for GlyphGuard.

Every table in this module is hand-curated from Unicode character names and
publicly documented confusable/homoglyph research (UTS #39 skeleton algorithm,
Unicode Technical Report #36, and the Trojan Source study behind
CVE-2021-42574).  The tables are intentionally conservative: only mappings
that are unambiguous and well-known are included, so the audit produces
high-signal findings instead of noise.

Pure standard library, zero third-party dependencies.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Curated homoglyph / confusable table (source char -> ASCII base char).
# Sources: UTS #39 confusables, codebox/homoglyph, Unicode security guide.
# ---------------------------------------------------------------------------

CONFUSABLES = {
    # -- Cyrillic lowercase ------------------------------------------------
    "\u0430": "a",  # CYRILLIC SMALL LETTER A
    "\u0432": "b",  # CYRILLIC SMALL LETTER VE (looks like Latin b)
    "\u0435": "e",  # CYRILLIC SMALL LETTER IE
    "\u043a": "k",  # CYRILLIC SMALL LETTER KA
    "\u043c": "m",  # CYRILLIC SMALL LETTER EM
    "\u043e": "o",  # CYRILLIC SMALL LETTER O
    "\u043f": "n",  # CYRILLIC SMALL LETTER PE (looks like Latin n)
    "\u0440": "p",  # CYRILLIC SMALL LETTER ER
    "\u0441": "c",  # CYRILLIC SMALL LETTER ES
    "\u0443": "y",  # CYRILLIC SMALL LETTER U
    "\u0445": "x",  # CYRILLIC SMALL LETTER HA
    "\u0455": "s",  # CYRILLIC SMALL LETTER DZE
    "\u0456": "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0458": "j",  # CYRILLIC SMALL LETTER JE
    "\u0475": "v",  # CYRILLIC SMALL LETTER IZHITSA
    "\u04bb": "h",  # CYRILLIC SMALL LETTER SHHA
    "\u04cf": "l",  # CYRILLIC SMALL LETTER PALOCHKA
    "\u0501": "d",  # CYRILLIC SMALL LETTER KOMI DE
    "\u051b": "q",  # CYRILLIC SMALL LETTER QA
    "\u051d": "w",  # CYRILLIC SMALL LETTER WE
    # -- Cyrillic uppercase ------------------------------------------------
    "\u0410": "A",  # CYRILLIC CAPITAL LETTER A
    "\u0412": "B",  # CYRILLIC CAPITAL LETTER VE
    "\u0415": "E",  # CYRILLIC CAPITAL LETTER IE
    "\u0417": "3",  # CYRILLIC CAPITAL LETTER ZE (looks like digit 3)
    "\u041a": "K",  # CYRILLIC CAPITAL LETTER KA
    "\u041c": "M",  # CYRILLIC CAPITAL LETTER EM
    "\u041d": "H",  # CYRILLIC CAPITAL LETTER EN
    "\u041e": "O",  # CYRILLIC CAPITAL LETTER O
    "\u0420": "P",  # CYRILLIC CAPITAL LETTER ER
    "\u0421": "C",  # CYRILLIC CAPITAL LETTER ES
    "\u0422": "T",  # CYRILLIC CAPITAL LETTER TE
    "\u0425": "X",  # CYRILLIC CAPITAL LETTER HA
    "\u0406": "I",  # CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0408": "J",  # CYRILLIC CAPITAL LETTER JE
    # -- Greek --------------------------------------------------------------
    "\u0391": "A",  # GREEK CAPITAL LETTER ALPHA
    "\u0392": "B",  # GREEK CAPITAL LETTER BETA
    "\u0395": "E",  # GREEK CAPITAL LETTER EPSILON
    "\u0396": "Z",  # GREEK CAPITAL LETTER ZETA
    "\u0397": "H",  # GREEK CAPITAL LETTER ETA
    "\u0399": "I",  # GREEK CAPITAL LETTER IOTA
    "\u039a": "K",  # GREEK CAPITAL LETTER KAPPA
    "\u039c": "M",  # GREEK CAPITAL LETTER MU
    "\u039d": "N",  # GREEK CAPITAL LETTER NU
    "\u039f": "O",  # GREEK CAPITAL LETTER OMICRON
    "\u03a1": "P",  # GREEK CAPITAL LETTER RHO
    "\u03a4": "T",  # GREEK CAPITAL LETTER TAU
    "\u03a5": "Y",  # GREEK CAPITAL LETTER UPSILON
    "\u03a7": "X",  # GREEK CAPITAL LETTER CHI
    "\u03b1": "a",  # GREEK SMALL LETTER ALPHA
    "\u03b9": "i",  # GREEK SMALL LETTER IOTA
    "\u03bf": "o",  # GREEK SMALL LETTER OMICRON
    "\u03c1": "p",  # GREEK SMALL LETTER RHO
    "\u03c7": "x",  # GREEK SMALL LETTER CHI
    "\u03f2": "c",  # GREEK LUNATE SIGMA SYMBOL
    # -- Armenian / others ---------------------------------------------------
    "\u0585": "o",  # ARMENIAN SMALL LETTER OH
    "\u0261": "g",  # LATIN SMALL LETTER SCRIPT G
    "\u0251": "a",  # LATIN SMALL LETTER ALPHA
    "\u02bc": "'",  # MODIFIER LETTER APOSTROPHE
    "\u2018": "'",  # LEFT SINGLE QUOTATION MARK
    "\u2019": "'",  # RIGHT SINGLE QUOTATION MARK
    "\u207f": "n",  # SUPERSCRIPT LATIN SMALL LETTER N
    # -- Letterlike Symbols (single code points) ------------------------------
    "\u2102": "C",  # DOUBLE-STRUCK CAPITAL C
    "\u210b": "H",  # SCRIPT CAPITAL H
    "\u210c": "H",  # BLACK-LETTER CAPITAL H
    "\u210d": "H",  # DOUBLE-STRUCK CAPITAL H
    "\u210e": "h",  # PLANCK CONSTANT
    "\u210f": "h",  # PLANCK CONSTANT OVER TWO PI
    "\u2110": "I",  # SCRIPT CAPITAL I
    "\u2111": "I",  # BLACK-LETTER CAPITAL I
    "\u2112": "L",  # SCRIPT CAPITAL L
    "\u2113": "l",  # SCRIPT SMALL L
    "\u2115": "N",  # DOUBLE-STRUCK CAPITAL N
    "\u2119": "P",  # DOUBLE-STRUCK CAPITAL P
    "\u211a": "Q",  # DOUBLE-STRUCK CAPITAL Q
    "\u211b": "R",  # SCRIPT CAPITAL R
    "\u211c": "R",  # BLACK-LETTER CAPITAL R
    "\u211d": "R",  # DOUBLE-STRUCK CAPITAL R
    "\u2124": "Z",  # DOUBLE-STRUCK CAPITAL Z
    "\u212a": "K",  # KELVIN SIGN
    "\u212b": "A",  # ANGSTROM SIGN
    "\u212c": "B",  # BLACK-LETTER CAPITAL B
    "\u212d": "C",  # BLACK-LETTER CAPITAL C
    "\u212f": "e",  # SCRIPT SMALL E
    "\u2130": "E",  # SCRIPT CAPITAL E
    "\u2131": "F",  # SCRIPT CAPITAL F
    "\u2133": "M",  # SCRIPT CAPITAL M
    "\u2134": "o",  # SCRIPT SMALL O
    "\u210a": "g",  # SCRIPT SMALL G
    # -- Alphabetic Presentation Forms (ligatures) -----------------------------
    "\ufb00": "ff",
    "\ufb01": "fi",
    "\ufb02": "fl",
    "\ufb03": "ffi",
    "\ufb04": "ffl",
}

# ---------------------------------------------------------------------------
# Algorithmic confusable ranges.
# Each entry: (start_codepoint, end_codepoint, base_offset) where
# base = chr(codepoint + base_offset).  Only solid (hole-free) ranges are
# listed; gapped ranges (script / fraktur / double-struck letters) are
# flagged separately via MATH_LETTER_RANGE.
# ---------------------------------------------------------------------------

ALGORITHMIC_CONFUSABLES = [
    # Fullwidth ASCII variants (FF01..FF5E -> 0x21..0x7E)
    (0xFF01, 0xFF5E, -0xFEE0),
    # Mathematical Bold A-Z / a-z
    (0x1D400, 0x1D419, -0x1D3BF),
    (0x1D41A, 0x1D433, -0x1D3B9),
    # Mathematical Italic A-Z / a-z
    (0x1D434, 0x1D44D, -0x1D3F3),
    (0x1D44E, 0x1D467, -0x1D3ED),
    # Mathematical Bold Italic A-Z / a-z
    (0x1D468, 0x1D481, -0x1D427),
    (0x1D482, 0x1D49B, -0x1D421),
    # Mathematical Monospace A-Z / a-z
    (0x1D670, 0x1D689, -0x1D62F),
    (0x1D68A, 0x1D6A3, -0x1D629),
    # Mathematical Sans-Serif A-Z / a-z
    (0x1D5A0, 0x1D5B9, -0x1D55F),
    (0x1D5BA, 0x1D5D3, -0x1D559),
    # Mathematical Sans-Serif Bold A-Z / a-z
    (0x1D5D4, 0x1D5ED, -0x1D593),
    (0x1D5EE, 0x1D607, -0x1D58D),
    # Mathematical digit variants (bold, double-struck, sans, sans-bold, mono)
    (0x1D7CE, 0x1D7D7, -0x1D79E),
    (0x1D7D8, 0x1D7E1, -0x1D7A8),
    (0x1D7E2, 0x1D7EB, -0x1D7B2),
    (0x1D7EC, 0x1D7F5, -0x1D7BC),
    (0x1D7F6, 0x1D7FF, -0x1D7C6),
    # Enclosed (circled) Latin letters
    (0x24B6, 0x24CF, -0x2475),  # CIRCLED LATIN CAPITAL LETTER A..Z
    (0x24D0, 0x24E9, -0x246F),  # CIRCLED LATIN SMALL LETTER A..Z
]

# Mathematical alphanumeric ranges that are flagged but not mapped to a base
# character (they contain holes, so a naive offset mapping would be wrong).
MATH_LETTER_RANGE = (0x1D49C, 0x1D59F)  # script / fraktur / double-struck letters

# ---------------------------------------------------------------------------
# Invisible / format characters.  char -> (severity, description)
# severity: "critical" for bidirectional overrides (Trojan Source class),
#           "warning" for everything else.
# ---------------------------------------------------------------------------

INVISIBLE_CHARS = {
    # Bidirectional overrides and isolates -- the Trojan Source attack class
    "\u202a": ("critical", "LEFT-TO-RIGHT EMBEDDING"),
    "\u202b": ("critical", "RIGHT-TO-LEFT EMBEDDING"),
    "\u202c": ("critical", "POP DIRECTIONAL FORMATTING"),
    "\u202d": ("critical", "LEFT-TO-RIGHT OVERRIDE"),
    "\u202e": ("critical", "RIGHT-TO-LEFT OVERRIDE"),
    "\u2066": ("critical", "LEFT-TO-RIGHT ISOLATE"),
    "\u2067": ("critical", "RIGHT-TO-LEFT ISOLATE"),
    "\u2068": ("critical", "FIRST STRONG ISOLATE"),
    "\u2069": ("critical", "POP DIRECTIONAL ISOLATE"),
    # Zero-width and joining characters
    "\u200b": ("warning", "ZERO WIDTH SPACE"),
    "\u200c": ("warning", "ZERO WIDTH NON-JOINER"),
    "\u200d": ("warning", "ZERO WIDTH JOINER"),
    "\u2060": ("warning", "WORD JOINER"),
    "\ufeff": ("warning", "ZERO WIDTH NO-BREAK SPACE (BOM)"),
    "\u00ad": ("warning", "SOFT HYPHEN"),
    "\u180e": ("warning", "MONGOLIAN VOWEL SEPARATOR"),
    "\u061c": ("warning", "ARABIC LETTER MARK"),
    # Bidirectional marks (weaker than overrides, still suspicious)
    "\u200e": ("warning", "LEFT-TO-RIGHT MARK"),
    "\u200f": ("warning", "RIGHT-TO-LEFT MARK"),
    # Invisible math operators
    "\u2061": ("warning", "FUNCTION APPLICATION"),
    "\u2062": ("warning", "INVISIBLE TIMES"),
    "\u2063": ("warning", "INVISIBLE SEPARATOR"),
    "\u2064": ("warning", "INVISIBLE PLUS"),
    # Variation selectors (invisible by design)
    "\ufe00": ("warning", "VARIATION SELECTOR-1"),
    "\ufe0f": ("warning", "VARIATION SELECTOR-16"),
    # Interlinear annotation anchors
    "\ufff9": ("warning", "INTERLINEAR ANNOTATION ANCHOR"),
    "\ufffa": ("warning", "INTERLINEAR ANNOTATION SEPARATOR"),
    "\ufffb": ("warning", "INTERLINEAR ANNOTATION TERMINATOR"),
    # Combining grapheme joiner and Hangul fillers
    "\u034f": ("warning", "COMBINING GRAPHEME JOINER"),
    "\u115f": ("warning", "HANGUL CHOSEONG FILLER"),
    "\u1160": ("warning", "HANGUL JUNGSEONG FILLER"),
    "\u3164": ("warning", "HANGUL FILLER"),
    "\uffa0": ("warning", "HALFWIDTH HANGUL FILLER"),
    # Braille pattern blank (renders as empty space)
    "\u2800": ("warning", "BRAILLE PATTERN BLANK"),
}

# Range-based invisible characters: (start, end, severity, description)
INVISIBLE_RANGES = [
    (0xE0000, 0xE007F, "warning", "TAG character (invisible)"),
    (0xE0100, 0xE01EF, "warning", "VARIATION SELECTOR (supplement)"),
]

# Control characters that are always suspicious.
CONTROL_NUL = "\u0000"
CONTROL_ALLOWED = {"\t", "\n", "\r"}

# ---------------------------------------------------------------------------
# Script detection.  Primary strategy: Unicode character name prefix, which is
# self-maintaining across Unicode versions.  The explicit range table below
# only covers cases where the name prefix is unreliable.
# ---------------------------------------------------------------------------

SCRIPT_NAME_PREFIXES = [
    ("CJK", "Han"),
    ("KANGXI", "Han"),
    ("IDEOGRAPHIC", "Han"),
    ("HIRAGANA", "Hiragana"),
    ("KATAKANA", "Katakana"),
    ("HANGUL", "Hangul"),
    ("BOPOMOFO", "Bopomofo"),
    ("LATIN", "Latin"),
    ("GREEK", "Greek"),
    ("COPTIC", "Coptic"),
    ("CYRILLIC", "Cyrillic"),
    ("ARMENIAN", "Armenian"),
    ("GEORGIAN", "Georgian"),
    ("HEBREW", "Hebrew"),
    ("ARABIC", "Arabic"),
    ("SYRIAC", "Syriac"),
    ("THAANA", "Thaana"),
    ("NKO", "NKo"),
    ("SAMARITAN", "Samaritan"),
    ("MANDAIC", "Mandaic"),
    ("DEVANAGARI", "Indic"),
    ("BENGALI", "Indic"),
    ("GURMUKHI", "Indic"),
    ("GUJARATI", "Indic"),
    ("ORIYA", "Indic"),
    ("TAMIL", "Indic"),
    ("TELUGU", "Indic"),
    ("KANNADA", "Indic"),
    ("MALAYALAM", "Indic"),
    ("SINHALA", "Indic"),
    ("THAI", "Thai"),
    ("LAO", "Lao"),
    ("TIBETAN", "Tibetan"),
    ("MYANMAR", "Myanmar"),
    ("GEORGIAN", "Georgian"),
    ("ETHIOPIC", "Ethiopic"),
    ("CHEROKEE", "Cherokee"),
    ("CANADIAN", "Canadian Aboriginal"),
    ("MONGOLIAN", "Mongolian"),
    ("OGHAM", "Ogham"),
    ("RUNIC", "Runic"),
    ("TAGALOG", "Philippine"),
    ("HANUNOO", "Philippine"),
    ("BUHID", "Philippine"),
    ("TAGBANWA", "Philippine"),
    ("KHMER", "Khmer"),
    ("DESERET", "Deseret"),
    ("SHAVIAN", "Shavian"),
    ("OSMANYA", "Osmanya"),
    ("TIFINAGH", "Tifinagh"),
    ("NEWA", "Newa"),
    ("ADLAM", "Adlam"),
    ("VAI", "Vai"),
    ("BRAILLE", "Braille"),
]

# Ranges where the name prefix is unreliable.
SCRIPT_RANGE_OVERRIDES = [
    (0x0000, 0x001F, "Control"),   # C0 controls
    (0x007F, 0x009F, "Control"),   # DEL + C1 controls
    (0x0378, 0x0379, "Unknown"),
    (0x0380, 0x0383, "Unknown"),
    (0x038B, 0x038B, "Unknown"),
    (0x038D, 0x038D, "Unknown"),
    (0x03A2, 0x03A2, "Unknown"),
    (0x0530, 0x0530, "Unknown"),
    (0x0557, 0x0558, "Unknown"),
    (0x058B, 0x058C, "Unknown"),
    (0x0590, 0x05FF, "Hebrew"),
    (0x05C7, 0x05C7, "Hebrew"),
    (0x1D400, 0x1D7FF, "Math"),
    (0x1D800, 0x1DFFF, "SignWriting"),
    (0xE0000, 0xE007F, "Format"),
    (0xE0100, 0xE01EF, "Inherited"),
    (0xF0000, 0x10FFFF, "Private Use"),
]

# Scripts that are frequently combined with Han in legitimate CJK text.
CJK_SCRIPTS = {"Han", "Hiragana", "Katakana", "Hangul", "Bopomofo"}

# Scripts that look like Latin and are commonly used for spoofing.
LATIN_LOOKALIKE_SCRIPTS = {
    "Cyrillic",
    "Greek",
    "Coptic",
    "Armenian",
    "Georgian",
    "Cherokee",
    "Deseret",
    "Shavian",
    "Osmanya",
}

# Scripts that never mix with Latin inside a single word in legitimate text.
EXOTIC_SCRIPTS = {
    "Arabic",
    "Hebrew",
    "Syriac",
    "Thaana",
    "NKo",
    "Samaritan",
    "Mandaic",
    "Indic",
    "Thai",
    "Lao",
    "Tibetan",
    "Myanmar",
    "Khmer",
    "Ethiopic",
    "Mongolian",
    "Tifinagh",
    "Vai",
    "Adlam",
    "Runic",
    "Ogham",
    "Canadian Aboriginal",
    "Philippine",
    "SignWriting",
}

# ---------------------------------------------------------------------------
# Common Unicode blocks (compact table for the `inspect` command).
# ---------------------------------------------------------------------------

COMMON_BLOCKS = [
    (0x0000, 0x007F, "Basic Latin"),
    (0x0080, 0x00FF, "Latin-1 Supplement"),
    (0x0100, 0x017F, "Latin Extended-A"),
    (0x0180, 0x024F, "Latin Extended-B"),
    (0x0250, 0x02AF, "IPA Extensions"),
    (0x02B0, 0x02FF, "Spacing Modifier Letters"),
    (0x0300, 0x036F, "Combining Diacritical Marks"),
    (0x0370, 0x03FF, "Greek and Coptic"),
    (0x0400, 0x04FF, "Cyrillic"),
    (0x0500, 0x052F, "Cyrillic Supplement"),
    (0x0530, 0x058F, "Armenian"),
    (0x0590, 0x05FF, "Hebrew"),
    (0x0600, 0x06FF, "Arabic"),
    (0x0700, 0x074F, "Syriac"),
    (0x0750, 0x077F, "Arabic Supplement"),
    (0x0780, 0x07BF, "Thaana"),
    (0x07C0, 0x07FF, "NKo"),
    (0x0800, 0x083F, "Samaritan"),
    (0x0840, 0x085F, "Mandaic"),
    (0x0900, 0x097F, "Devanagari"),
    (0x0980, 0x09FF, "Bengali"),
    (0x0A00, 0x0A7F, "Gurmukhi"),
    (0x0A80, 0x0AFF, "Gujarati"),
    (0x0B00, 0x0B7F, "Oriya"),
    (0x0B80, 0x0BFF, "Tamil"),
    (0x0C00, 0x0C7F, "Telugu"),
    (0x0C80, 0x0CFF, "Kannada"),
    (0x0D00, 0x0D7F, "Malayalam"),
    (0x0D80, 0x0DFF, "Sinhala"),
    (0x0E00, 0x0E7F, "Thai"),
    (0x0E80, 0x0EFF, "Lao"),
    (0x0F00, 0x0FFF, "Tibetan"),
    (0x1000, 0x109F, "Myanmar"),
    (0x10A0, 0x10FF, "Georgian"),
    (0x1100, 0x11FF, "Hangul Jamo"),
    (0x1E00, 0x1EFF, "Latin Extended Additional"),
    (0x1F00, 0x1FFF, "Greek Extended"),
    (0x2000, 0x206F, "General Punctuation"),
    (0x2070, 0x209F, "Superscripts and Subscripts"),
    (0x20A0, 0x20CF, "Currency Symbols"),
    (0x20D0, 0x20FF, "Combining Marks for Symbols"),
    (0x2100, 0x214F, "Letterlike Symbols"),
    (0x2150, 0x218F, "Number Forms"),
    (0x2190, 0x21FF, "Arrows"),
    (0x2200, 0x22FF, "Mathematical Operators"),
    (0x2300, 0x23FF, "Miscellaneous Technical"),
    (0x2400, 0x243F, "Control Pictures"),
    (0x2440, 0x245F, "Optical Character Recognition"),
    (0x2460, 0x24FF, "Enclosed Alphanumerics"),
    (0x2500, 0x257F, "Box Drawing"),
    (0x2580, 0x259F, "Block Elements"),
    (0x25A0, 0x25FF, "Geometric Shapes"),
    (0x2600, 0x26FF, "Miscellaneous Symbols"),
    (0x2700, 0x27BF, "Dingbats"),
    (0x2C60, 0x2C7F, "Latin Extended-C"),
    (0x2D00, 0x2D2F, "Georgian Supplement"),
    (0x2D30, 0x2D7F, "Tifinagh"),
    (0x2D80, 0x2DDF, "Ethiopic Supplement"),
    (0x2E80, 0x2EFF, "CJK Radicals Supplement"),
    (0x2F00, 0x2FDF, "Kangxi Radicals"),
    (0x3000, 0x303F, "CJK Symbols and Punctuation"),
    (0x3040, 0x309F, "Hiragana"),
    (0x30A0, 0x30FF, "Katakana"),
    (0x3100, 0x312F, "Bopomofo"),
    (0x3130, 0x318F, "Hangul Compatibility Jamo"),
    (0x3190, 0x319F, "Kanbun"),
    (0x31A0, 0x31BF, "Bopomofo Extended"),
    (0x31F0, 0x31FF, "Katakana Phonetic Extensions"),
    (0x3200, 0x32FF, "Enclosed CJK Letters and Months"),
    (0x3300, 0x33FF, "CJK Compatibility"),
    (0x3400, 0x4DBF, "CJK Unified Ideographs Extension A"),
    (0x4DC0, 0x4DFF, "Yijing Hexagram Symbols"),
    (0x4E00, 0x9FFF, "CJK Unified Ideographs"),
    (0xA000, 0xA48F, "Yi Syllables"),
    (0xA490, 0xA4CF, "Yi Radicals"),
    (0xA640, 0xA69F, "Cyrillic Extended-B"),
    (0xA720, 0xA7FF, "Latin Extended-D"),
    (0xAC00, 0xD7AF, "Hangul Syllables"),
    (0xE000, 0xF8FF, "Private Use Area"),
    (0xF900, 0xFAFF, "CJK Compatibility Ideographs"),
    (0xFB00, 0xFB4F, "Alphabetic Presentation Forms"),
    (0xFB50, 0xFDFF, "Arabic Presentation Forms-A"),
    (0xFE00, 0xFE0F, "Variation Selectors"),
    (0xFE20, 0xFE2F, "Combining Half Marks"),
    (0xFE30, 0xFE4F, "CJK Compatibility Forms"),
    (0xFE50, 0xFE6F, "Small Form Variants"),
    (0xFE70, 0xFEFF, "Arabic Presentation Forms-B"),
    (0xFF00, 0xFFEF, "Halfwidth and Fullwidth Forms"),
    (0xFFF0, 0xFFFF, "Specials"),
    (0x10000, 0x1007F, "Linear B Syllabary"),
    (0x10080, 0x100FF, "Linear B Ideograms"),
    (0x10100, 0x1013F, "Aegean Numbers"),
    (0x10300, 0x1032F, "Old Italic"),
    (0x10330, 0x1034F, "Gothic"),
    (0x10400, 0x1044F, "Deseret"),
    (0x10450, 0x1047F, "Shavian"),
    (0x10480, 0x104AF, "Osmanya"),
    (0x10500, 0x1052F, "Elbasan"),
    (0x10A00, 0x10A5F, "Kharoshthi"),
    (0x11000, 0x1107F, "Brahmi"),
    (0x1D000, 0x1D0FF, "Byzantine Musical Symbols"),
    (0x1D100, 0x1D1FF, "Musical Symbols"),
    (0x1D200, 0x1D24F, "Ancient Greek Musical Notation"),
    (0x1D300, 0x1D35F, "Tai Xuan Jing Symbols"),
    (0x1D360, 0x1D37F, "Counting Rod Numerals"),
    (0x1D400, 0x1D7FF, "Mathematical Alphanumeric Symbols"),
    (0x1D800, 0x1DAAF, "Sutton SignWriting"),
    (0x1E900, 0x1E95F, "Adlam"),
    (0x1EE00, 0x1EEFF, "Arabic Mathematical Alphabetic Symbols"),
    (0x1F000, 0x1F02F, "Mahjong Tiles"),
    (0x1F030, 0x1F09F, "Domino Tiles"),
    (0x1F0A0, 0x1F0FF, "Playing Cards"),
    (0x1F100, 0x1F1FF, "Enclosed Alphanumeric Supplement"),
    (0x1F200, 0x1F2FF, "Enclosed Ideographic Supplement"),
    (0x1F300, 0x1F5FF, "Miscellaneous Symbols and Pictographs"),
    (0x1F600, 0x1F64F, "Emoticons"),
    (0x1F650, 0x1F67F, "Ornamental Dingbats"),
    (0x1F680, 0x1F6FF, "Transport and Map Symbols"),
    (0x1F700, 0x1F77F, "Alchemical Symbols"),
    (0x1F780, 0x1F7FF, "Geometric Shapes Extended"),
    (0x1F800, 0x1F8FF, "Supplemental Arrows-C"),
    (0x1F900, 0x1F9FF, "Supplemental Symbols and Pictographs"),
    (0x1FA00, 0x1FA6F, "Chess Symbols"),
    (0x1FA70, 0x1FAFF, "Symbols and Pictographs Extended-A"),
    (0x20000, 0x2A6DF, "CJK Unified Ideographs Extension B"),
    (0x2A700, 0x2B73F, "CJK Unified Ideographs Extension C"),
    (0x2B740, 0x2B81F, "CJK Unified Ideographs Extension D"),
    (0x2B820, 0x2CEAF, "CJK Unified Ideographs Extension E"),
    (0x2CEB0, 0x2EBEF, "CJK Unified Ideographs Extension F"),
    (0x2F800, 0x2FA1F, "CJK Compatibility Ideographs Supplement"),
    (0x30000, 0x3134F, "CJK Unified Ideographs Extension G"),
    (0x31350, 0x323AF, "CJK Unified Ideographs Extension H"),
    (0xE0000, 0xE007F, "Tags"),
    (0xE0100, 0xE01EF, "Variation Selectors Supplement"),
    (0xF0000, 0xFFFFD, "Supplementary Private Use Area-A"),
    (0x100000, 0x10FFFD, "Supplementary Private Use Area-B"),
]

# ---------------------------------------------------------------------------
# Text file extensions audited by default.
# ---------------------------------------------------------------------------

TEXT_EXTENSIONS = {
    ".py", ".pyw", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".java", ".kt", ".kts", ".scala", ".groovy", ".gradle", ".go", ".rs",
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".cs", ".fs", ".vb",
    ".rb", ".php", ".swift", ".m", ".mm", ".dart", ".lua", ".pl", ".pm",
    ".r", ".jl", ".ex", ".exs", ".erl", ".hrl", ".clj", ".cljs", ".hs",
    ".ml", ".nim", ".cr", ".zig", ".v", ".sv", ".vhd", ".asm", ".s",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd",
    ".sql", ".psql", ".mysql", ".html", ".htm", ".xhtml", ".xml", ".svg",
    ".css", ".scss", ".sass", ".less", ".vue", ".svelte", ".astro",
    ".json", ".json5", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".properties", ".env", ".editorconfig", ".gitignore",
    ".gitattributes", ".dockerignore", ".md", ".mdx", ".markdown", ".rst",
    ".txt", ".text", ".csv", ".tsv", ".tex", ".bib", ".org", ".adoc",
    ".proto", ".graphql", ".gql", ".tf", ".tfvars", ".hcl", ".bicep",
    ".cmake", ".mk", ".make", ".makefile", ".dockerfile", ".containerfile",
    ".nix", ".just", ".cabal", ".el", ".lisp", ".scm", ".rkt", ".f90",
    ".for", ".f", ".pas", ".d", ".coffee", ".litcoffee", ".sml",
}

# Directories skipped by default during recursive audits.
DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", ".venv", "venv", "env",
    ".idea", ".vscode", "dist", "build", "target", "out", ".next",
    ".nuxt", ".svelte-kit", "coverage", ".gradle", ".dart_tool",
}
