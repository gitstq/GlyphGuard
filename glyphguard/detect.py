"""Detection logic for GlyphGuard.

Turns raw text into structured :class:`Finding` objects for every class of
Unicode security risk the engine understands: invisible/format characters,
bidirectional (Trojan Source) overrides, control characters, homoglyphs,
mixed-script spoofing and non-normalized text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from . import core, data

__all__ = [
    "Finding",
    "find_invisibles",
    "find_control",
    "find_confusables",
    "find_mixed_scripts",
    "find_non_normalized",
    "check_domain",
]


@dataclass
class Finding:
    """A single security finding."""

    kind: str
    severity: str  # "critical" | "warning" | "info"
    line: int
    col: int
    index: int
    char: Optional[str]
    codepoint: str
    name: str
    message: str
    context: str
    suggestion: str

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "line": self.line,
            "col": self.col,
            "char": self.char,
            "codepoint": self.codepoint,
            "name": self.name,
            "message": self.message,
            "context": self.context,
            "suggestion": self.suggestion,
        }


# ---------------------------------------------------------------------------
# Context helpers
# ---------------------------------------------------------------------------

def _line_context(text: str, index: int, width: int = 60) -> str:
    line_start = text.rfind("\n", 0, index) + 1
    line_end = text.find("\n", index)
    if line_end == -1:
        line_end = len(text)
    snippet = text[line_start:line_end]
    if len(snippet) > width:
        snippet = snippet[:width] + "…"
    return snippet.replace("\t", "    ")


# ---------------------------------------------------------------------------
# Invisible / format characters
# ---------------------------------------------------------------------------

def find_invisibles(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        sev_name = data.INVISIBLE_CHARS.get(ch)
        if sev_name is not None:
            severity, name = sev_name
            line, col = core.line_col(text, i)
            kind = "bidi" if severity == "critical" else "invisible"
            message = (
                "%s detected — can reorder or hide surrounding text"
                % name
                if kind == "bidi"
                else "%s detected — invisible, often used to smuggle text" % name
            )
            findings.append(
                Finding(
                    kind=kind,
                    severity=severity,
                    line=line,
                    col=col,
                    index=i,
                    char=ch,
                    codepoint="U+%04X" % cp,
                    name=name,
                    message=message,
                    context=_line_context(text, i),
                    suggestion=(
                        "remove the override or balance it with a matching "
                        "pop (U+202C / U+2069)"
                        if kind == "bidi"
                        else "remove the character or use clean_text()"
                    ),
                )
            )
        else:
            for start, end, severity, name in data.INVISIBLE_RANGES:
                if start <= cp <= end:
                    line, col = core.line_col(text, i)
                    findings.append(
                        Finding(
                            kind="invisible",
                            severity=severity,
                            line=line,
                            col=col,
                            index=i,
                            char=ch,
                            codepoint="U+%04X" % cp,
                            name=name,
                            message="%s detected — invisible" % name,
                            context=_line_context(text, i),
                            suggestion="remove the character or use clean_text()",
                        )
                    )
                    break
    return findings


# ---------------------------------------------------------------------------
# Control characters
# ---------------------------------------------------------------------------

def find_control(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for i, ch in enumerate(text):
        if ch in data.CONTROL_ALLOWED:
            continue
        if ord(ch) == 0:  # NUL is especially dangerous in source
            line, col = core.line_col(text, i)
            findings.append(
                Finding(
                    kind="control",
                    severity="critical",
                    line=line,
                    col=col,
                    index=i,
                    char=ch,
                    codepoint="U+0000",
                    name="NULL",
                    message="NUL byte detected — can truncate strings or break parsers",
                    context=_line_context(text, i),
                    suggestion="remove the NUL byte",
                )
            )
        elif core.char_info(ch).category == "Cc":
            line, col = core.line_col(text, i)
            findings.append(
                Finding(
                    kind="control",
                    severity="warning",
                    line=line,
                    col=col,
                    index=i,
                    char=ch,
                    codepoint="U+%04X" % ord(ch),
                    name=core.char_info(ch).name,
                    message="control character U+%04X detected" % ord(ch),
                    context=_line_context(text, i),
                    suggestion="remove or replace the control character",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Homoglyph / confusable detection
# ---------------------------------------------------------------------------

def _is_math_letter(ch: str) -> bool:
    cp = ord(ch)
    return data.MATH_LETTER_RANGE[0] <= cp <= data.MATH_LETTER_RANGE[1]


def find_confusables(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for start, word in core.iter_words(text):
        has_ascii_letter = any(c.isascii() and c.isalpha() for c in word)
        for j, ch in enumerate(word):
            base = core.confusable_base(ch)
            is_confusable = base is not None and not ch.isascii()
            is_math = _is_math_letter(ch)
            if not (is_confusable or is_math):
                continue
            # A confusable only matters when it can be confused with a real
            # ASCII word (e.g. "аррlе" looking like "apple").
            if not has_ascii_letter and not is_math:
                continue
            line, col = core.line_col(text, start + j)
            if is_math:
                disp_base = ""
                sev = "warning"
                kind = "math-symbol"
                message = (
                    "mathematical alphanumeric letter detected — visually "
                    "mimics ASCII and is a common homoglyph vector"
                )
                suggestion = "replace with the ASCII letter"
            else:
                disp_base = " -> %r" % base
                sev = "critical"
                kind = "confusable"
                message = (
                    "homoglyph %r%s — looks like an ASCII character but is "
                    "from another script" % (ch, disp_base)
                )
                suggestion = "replace with the ASCII character %r" % base
            findings.append(
                Finding(
                    kind=kind,
                    severity=sev,
                    line=line,
                    col=col,
                    index=start + j,
                    char=ch,
                    codepoint="U+%04X" % ord(ch),
                    name=core.char_info(ch).name,
                    message=message,
                    context=word,
                    suggestion=suggestion,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Mixed-script detection
# ---------------------------------------------------------------------------

def find_mixed_scripts(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for start, word in core.iter_words(text):
        scripts = set()
        has_latin = False
        for ch in word:
            s = core.script_of(ch)
            if s == "Latin":
                has_latin = True
            elif s not in ("Common", "Inherited", "Unknown"):
                scripts.add(s)
        if not scripts:
            continue
        # Pure CJK combinations (Han + Hiragana + Katakana + Hangul) are
        # legitimate, as is CJK text that also contains Latin words.
        if scripts <= data.CJK_SCRIPTS:
            continue
        latin_like = scripts & data.LATIN_LOOKALIKE_SCRIPTS
        exotic = scripts & data.EXOTIC_SCRIPTS
        # A Latin-lookalike script (Cyrillic/Greek/...) appearing together with
        # Latin letters inside one word is the canonical spoofing pattern.
        if latin_like and (has_latin or len(scripts) > 1):
            severity = "critical"
            rest = scripts - latin_like
            other = ", ".join(sorted(rest)) if rest else "Latin"
            message = (
                "word mixes %s with %s — classic spoofing pattern"
                % (", ".join(sorted(latin_like)), other)
            )
        elif exotic and has_latin:
            severity = "warning"
            message = "word mixes unrelated scripts: %s" % ", ".join(
                sorted(scripts | {"Latin"})
            )
        else:
            continue
        findings.append(
            Finding(
                kind="mixed-script",
                severity=severity,
                line=core.line_col(text, start)[0],
                col=core.line_col(text, start)[1],
                index=start,
                char=None,
                codepoint="",
                name="mixed script",
                message=message,
                context=word,
                suggestion="review the word; it may impersonate another",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Non-normalized text
# ---------------------------------------------------------------------------

def find_non_normalized(text: str) -> List[Finding]:
    findings: List[Finding] = []
    normalized = core.normalize_text(text, "NFC")
    if normalized == text:
        return findings
    for i, (ch, nch) in enumerate(zip(text, normalized)):
        if ch != nch:
            line, col = core.line_col(text, i)
            findings.append(
                Finding(
                    kind="non-normalized",
                    severity="info",
                    line=line,
                    col=col,
                    index=i,
                    char=ch,
                    codepoint="U+%04X" % ord(ch),
                    name=core.char_info(ch).name,
                    message=(
                        "non-NFC character U+%04X — normalizes to %r"
                        % (ord(ch), nch)
                    ),
                    context=_line_context(text, i),
                    suggestion="normalize the text to NFC",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Domain homograph audit
# ---------------------------------------------------------------------------

def check_domain(domain: str) -> Tuple[str, List[Finding]]:
    """Audit a domain name for homograph attacks.

    Returns ``(ascii_skeleton, findings)`` where *ascii_skeleton* is the
    punycode/ASCII rendering of the domain for display.
    """
    findings: List[Finding] = []
    labels = domain.split(".")
    skeleton_labels: List[str] = []
    for label in labels:
        unicode_label = label
        if label.lower().startswith("xn--"):
            try:
                unicode_label = label.encode("ascii").decode("idna")
            except Exception:
                unicode_label = label
        skeleton_labels.append(core.skeleton(unicode_label))
        # Analyze the decoded unicode label.
        for f in find_invisibles(unicode_label):
            f.context = label
            findings.append(f)
        for f in find_confusables(unicode_label):
            f.context = label
            findings.append(f)
        for f in find_mixed_scripts(unicode_label):
            f.context = label
            findings.append(f)
        if "/" in label or ":" in label:
            findings.append(
                Finding(
                    kind="malformed",
                    severity="warning",
                    line=1,
                    col=1,
                    index=0,
                    char=None,
                    codepoint="",
                    name="malformed",
                    message="domain contains reserved characters (/ or :)",
                    context=label,
                    suggestion="verify the input is a plain domain name",
                )
            )
    ascii_skeleton = ".".join(skeleton_labels)
    if "." not in domain and ascii_skeleton != skeleton_labels[0]:
        pass
    return ascii_skeleton, findings
