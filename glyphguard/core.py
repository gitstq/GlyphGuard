"""Core Unicode primitives for GlyphGuard.

Character introspection, script detection, display width, normalization,
skeleton computation and escape/unescape helpers.  Pure standard library.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import data

__all__ = [
    "CharInfo",
    "char_info",
    "script_of",
    "block_of",
    "display_width",
    "is_zero_width",
    "normalize_text",
    "clean_text",
    "skeleton",
    "escape_text",
    "unescape_text",
    "algorithmic_base",
]


@dataclass(frozen=True)
class CharInfo:
    """Structured information about a single character."""

    char: str
    codepoint: str
    name: str
    category: str
    block: str
    script: str
    east_asian_width: str
    bidi_class: str
    combining: bool
    confusable_base: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "char": self.char,
            "codepoint": self.codepoint,
            "name": self.name,
            "category": self.category,
            "block": self.block,
            "script": self.script,
            "east_asian_width": self.east_asian_width,
            "bidi_class": self.bidi_class,
            "combining": self.combining,
            "confusable_base": self.confusable_base,
        }


# ---------------------------------------------------------------------------
# Script / block detection
# ---------------------------------------------------------------------------

def _script_from_name(name: str) -> Optional[str]:
    for prefix, script in data.SCRIPT_NAME_PREFIXES:
        if name.startswith(prefix):
            return script
    return None


def script_of(char: str) -> str:
    """Return the script name of *char*.

    Uses the Unicode character name prefix (self-maintaining), falling back to
    an explicit range table for code points whose names are unreliable.
    Fullwidth/halfwidth forms inherit the script of their base character.
    """
    cp = ord(char)

    for start, end, script in data.SCRIPT_RANGE_OVERRIDES:
        if start <= cp <= end:
            if script == "Math":
                base = algorithmic_base(char)
                if base is not None and base.isascii() and base.isalpha():
                    return "Math (Latin look-alike)"
                return "Math"
            return script

    name = unicodedata.name(char, "")
    if not name:
        return "Unknown"

    # Fullwidth / halfwidth forms inherit their base character's script.
    if name.startswith("FULLWIDTH") or name.startswith("HALFWIDTH"):
        base = algorithmic_base(char)
        if base is not None:
            return script_of(base)

    script = _script_from_name(name)
    if script is not None:
        return script

    # Digits, punctuation and symbols shared across scripts.
    if name.startswith("DIGIT") or name.startswith(
        (
            "IDEOGRAPHIC", "HANGZHOU", "PARENTHESIZED", "CIRCLED",
            "NEGATIVE CIRCLED", "DOUBLE CIRCLED",
        )
    ):
        return "Common"
    category = unicodedata.category(char)
    if category in ("Nd", "Nl", "No"):
        return "Common"
    if category.startswith("P") or category.startswith("S"):
        return "Common"
    if category in ("Mn", "Me", "Mc", "Cf"):
        return "Inherited"
    return "Unknown"


def block_of(char: str) -> str:
    """Return the (common) Unicode block name of *char*."""
    cp = ord(char)
    for start, end, name in data.COMMON_BLOCKS:
        if start <= cp <= end:
            return name
    return "Unknown / Unassigned"


def algorithmic_base(char: str) -> Optional[str]:
    """Return the ASCII base character for algorithmic confusables.

    Covers fullwidth forms, mathematical alphanumerics (solid ranges only)
    and enclosed Latin letters.  Returns ``None`` when the character has no
    safe algorithmic mapping.
    """
    cp = ord(char)
    for start, end, offset in data.ALGORITHMIC_CONFUSABLES:
        if start <= cp <= end:
            base = chr(cp + offset)
            if base.isprintable():
                return base
            return None
    if data.MATH_LETTER_RANGE[0] <= cp <= data.MATH_LETTER_RANGE[1]:
        return None
    return None


def confusable_base(char: str) -> Optional[str]:
    """Return the skeleton base of *char* if it is a known confusable."""
    if char in data.CONFUSABLES:
        return data.CONFUSABLES[char]
    return algorithmic_base(char)


# ---------------------------------------------------------------------------
# Character information
# ---------------------------------------------------------------------------

def char_info(char: str) -> CharInfo:
    """Build a :class:`CharInfo` for a single character."""
    if len(char) != 1:
        raise ValueError("char_info() expects exactly one character")
    return CharInfo(
        char=char,
        codepoint="U+%04X" % ord(char),
        name=unicodedata.name(char, "<unnamed>"),
        category=unicodedata.category(char),
        block=block_of(char),
        script=script_of(char),
        east_asian_width=unicodedata.east_asian_width(char),
        bidi_class=unicodedata.bidirectional(char),
        combining=unicodedata.combining(char) != 0,
        confusable_base=confusable_base(char),
    )


# ---------------------------------------------------------------------------
# Display width
# ---------------------------------------------------------------------------

def is_zero_width(char: str) -> bool:
    """True when *char* renders with zero advance width."""
    cp = ord(char)
    category = unicodedata.category(char)
    if category in ("Mn", "Me", "Cf"):
        return True
    if cp in (0x200B, 0x200C, 0x200D, 0xFEFF):
        return True
    if unicodedata.combining(char) != 0:
        return True
    return False


def char_width(char: str) -> int:
    """Return the terminal display width of *char* (0, 1 or 2)."""
    if char in ("\n", "\r"):
        return 0
    if is_zero_width(char):
        return 0
    if unicodedata.east_asian_width(char) in ("W", "F"):
        return 2
    if unicodedata.category(char) in ("Cc",):
        return 0
    return 1


def display_width(text: str) -> int:
    """Return the total terminal display width of *text*."""
    return sum(char_width(ch) for ch in text)


# ---------------------------------------------------------------------------
# Normalization / cleaning
# ---------------------------------------------------------------------------

def normalize_text(text: str, form: str = "NFC") -> str:
    """Apply Unicode normalization.  ``form`` is one of NFC/NFD/NFKC/NFKD."""
    form = form.upper()
    if form not in ("NFC", "NFD", "NFKC", "NFKD"):
        raise ValueError("invalid normalization form: %r" % form)
    return unicodedata.normalize(form, text)


def clean_text(text: str, keep_newlines: bool = True) -> str:
    """Remove dangerous invisible/format characters and normalize to NFC.

    Removes: bidirectional overrides/isolates, zero-width characters, soft
    hyphens, BOMs, variation selectors, tag characters and (optionally) all
    control characters except tab/newline/carriage-return.
    """
    out: List[str] = []
    for ch in text:
        cp = ord(ch)
        category = unicodedata.category(ch)
        if category == "Cc":
            if ch in data.CONTROL_ALLOWED and (
                keep_newlines or ch not in ("\n", "\r")
            ):
                out.append(ch)
            continue
        if category == "Cf":
            continue
        if cp in data.INVISIBLE_CHARS:
            continue
        if 0xE0000 <= cp <= 0xE007F or 0xE0100 <= cp <= 0xE01EF:
            continue
        out.append(ch)
    return unicodedata.normalize("NFC", "".join(out))


# ---------------------------------------------------------------------------
# Skeleton (UTS #39 style, curated subset)
# ---------------------------------------------------------------------------

def skeleton(text: str) -> str:
    """Map *text* to its ASCII skeleton.

    Every known confusable character is replaced by its Latin/digit base.
    Characters without a known mapping are left untouched so that the
    skeleton stays diff-friendly.
    """
    return "".join(
        data.CONFUSABLES.get(ch) or algorithmic_base(ch) or ch for ch in text
    )


# ---------------------------------------------------------------------------
# Escape / unescape
# ---------------------------------------------------------------------------

def escape_text(text: str, style: str = "unicode") -> str:
    """Escape every non-ASCII (and control) character.

    Styles: ``unicode`` (\\uXXXX), ``html`` (&#xHH;) or ``name`` (\\N{...}).
    """
    style = style.lower()
    if style not in ("unicode", "html", "name"):
        raise ValueError("invalid escape style: %r" % style)
    out: List[str] = []
    for ch in text:
        cp = ord(ch)
        if ch in ("\t", "\n", "\r"):
            out.append(ch)
            continue
        if cp < 0x20 or cp == 0x7F or not ch.isprintable():
            if style == "unicode":
                if cp <= 0xFFFF:
                    out.append("\\u%04X" % cp)
                else:
                    out.append("\\U%08X" % cp)
            elif style == "html":
                out.append("&#x%X;" % cp)
            else:
                name = unicodedata.name(ch)
                out.append("\\N{%s}" % name)
        else:
            out.append(ch)
    return "".join(out)


def unescape_text(text: str) -> str:
    """Reverse :func:`escape_text` (unicode/html styles)."""
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "u" and i + 6 <= n:
                try:
                    out.append(chr(int(text[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            if nxt == "U" and i + 10 <= n:
                try:
                    out.append(chr(int(text[i + 2:i + 10], 16)))
                    i += 10
                    continue
                except ValueError:
                    pass
            if nxt == "N" and "{" in text[i:]:
                end = text.index("}", i)
                try:
                    out.append(unicodedata.lookup(text[i + 3:end]))
                    i = end + 1
                    continue
                except KeyError:
                    pass
            if nxt == "n":
                out.append("\n")
                i += 2
                continue
            if nxt == "t":
                out.append("\t")
                i += 2
                continue
            if nxt == "r":
                out.append("\r")
                i += 2
                continue
            if nxt == "\\":
                out.append("\\")
                i += 2
                continue
        if ch == "&" and i + 2 < n and text[i + 1] == "#":
            end = text.find(";", i)
            if end != -1:
                body = text[i + 2:end]
                try:
                    if body[:1] in ("x", "X"):
                        out.append(chr(int(body[1:], 16)))
                    else:
                        out.append(chr(int(body)))
                    i = end + 1
                    continue
                except ValueError:
                    pass
        out.append(ch)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Word splitting helpers
# ---------------------------------------------------------------------------

def iter_words(text: str) -> List[Tuple[int, str]]:
    """Split *text* into (start_index, word) pairs.

    A "word" is a maximal run of characters that are not whitespace and not
    common punctuation.  Used for per-word script-mixing analysis.
    """
    words: List[Tuple[int, str]] = []
    current: List[str] = []
    start = 0
    for i, ch in enumerate(text):
        if ch.isspace() or unicodedata.category(ch).startswith(("P", "Z", "C")):
            if current:
                words.append((start, "".join(current)))
                current = []
        else:
            if not current:
                start = i
            current.append(ch)
    if current:
        words.append((start, "".join(current)))
    return words


def line_col(text: str, index: int) -> Tuple[int, int]:
    """Convert a character *index* into 1-based (line, column)."""
    line = text.count("\n", 0, index) + 1
    last_nl = text.rfind("\n", 0, index)
    col = index - last_nl
    return line, col
