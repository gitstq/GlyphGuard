"""Report formatting for GlyphGuard (text, JSON and inspect views)."""

from __future__ import annotations

import json
from typing import Dict, List

from . import audit, core, detect
from .__init__ import __version__

__all__ = [
    "format_report",
    "format_reports",
    "format_json",
    "format_inspect",
]


# ---------------------------------------------------------------------------
# Color support
# ---------------------------------------------------------------------------

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _w(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return "%s%s%s" % (code, text, self.RESET)

    def bold(self, t: str) -> str:
        return self._w(self.BOLD, t)

    def dim(self, t: str) -> str:
        return self._w(self.DIM, t)

    def red(self, t: str) -> str:
        return self._w(self.RED, t)

    def yellow(self, t: str) -> str:
        return self._w(self.YELLOW, t)

    def blue(self, t: str) -> str:
        return self._w(self.BLUE, t)

    def cyan(self, t: str) -> str:
        return self._w(self.CYAN, t)

    def green(self, t: str) -> str:
        return self._w(self.GREEN, t)


SEVERITY_COLOR = {
    "critical": "red",
    "warning": "yellow",
    "info": "blue",
}


# ---------------------------------------------------------------------------
# Single report (text)
# ---------------------------------------------------------------------------

def format_report(report: audit.AuditReport, color: Color) -> str:
    lines: List[str] = []
    header = color.bold("GlyphGuard v%s — Unicode Security Audit" % __version__)
    lines.append(header)
    lines.append(color.dim("Target: %s" % report.target))
    score = report.score
    score_color = (
        color.green if score >= 90 else color.yellow if score >= 70 else color.red
    )
    lines.append(
        "Score: %s  (%s critical, %s warning, %s info)"
        % (
            score_color("%d/100" % score),
            color.red(str(report.critical)),
            color.yellow(str(report.warning)),
            color.blue(str(report.info)),
        )
    )
    lines.append(color.dim("─" * 56))

    if not report.findings:
        lines.append(color.green("✓  No issues found."))
        return "\n".join(lines)

    for f in report.findings:
        c = getattr(color, SEVERITY_COLOR.get(f.severity, "blue"))(f.severity.upper())
        loc = "L%d:C%d" % (f.line, f.col) if f.line else "—"
        codepoint = (" %s" % f.codepoint) if f.codepoint else ""
        lines.append(
            "[%s] %s  %s%s (%s)" % (c, loc, codepoint, f.name, f.kind)
        )
        lines.append("   %s" % f.message)
        if f.context:
            ctx = f.context.replace("\n", " ")
            if len(ctx) > 64:
                ctx = ctx[:64] + "…"
            lines.append(color.dim("   ctx: %s" % ctx))
        if f.suggestion:
            lines.append(color.cyan("   fix: %s" % f.suggestion))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Multiple reports (text)
# ---------------------------------------------------------------------------

def format_reports(reports: Dict[str, audit.AuditReport], color: Color) -> str:
    if not reports:
        return color.green("✓  No issues found across the audited paths.")
    blocks: List[str] = []
    total_crit = total_warn = total_info = 0
    for target, report in sorted(reports.items()):
        total_crit += report.critical
        total_warn += report.warning
        total_info += report.info
        blocks.append(format_report(report, color))
    summary = color.bold(
        "\nAggregated: %d files, %s critical, %s warning, %s info"
        % (
            len(reports),
            color.red(str(total_crit)),
            color.yellow(str(total_warn)),
            color.blue(str(total_info)),
        )
    )
    return "\n\n".join(blocks) + "\n\n" + summary


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def format_json(report: audit.AuditReport) -> str:
    return json.dumps(report.as_dict(), ensure_ascii=False, indent=2)


def format_reports_json(reports: Dict[str, audit.AuditReport]) -> str:
    payload = {
        "tool": "GlyphGuard",
        "version": __version__,
        "files": len(reports),
        "reports": [r.as_dict() for r in reports.values()],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Inspect view
# ---------------------------------------------------------------------------

def format_inspect(text: str, color: Color) -> str:
    lines: List[str] = []
    lines.append(
        color.bold(
            "%-4s %-8s %-12s %-26s %-5s %-3s %-14s"
            % ("idx", "cp", "char", "name", "cat", "w", "script")
        )
    )
    for i, ch in enumerate(text):
        info = core.char_info(ch)
        disp = ch if (ch.isprintable() and ch not in "\t\n\r") else "<%s>" % info.codepoint
        base = ("→%s" % info.confusable_base) if info.confusable_base else ""
        name = info.name
        if len(name) > 26:
            name = name[:23] + "…"
        lines.append(
            "%-4d %-8s %-12s %-26s %-5s %-3d %-14s"
            % (
                i,
                info.codepoint,
                (disp + base)[:12],
                name,
                info.category,
                core.char_width(ch),
                info.script[:14],
            )
        )
    return "\n".join(lines)
