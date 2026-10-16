"""Audit orchestration for GlyphGuard.

Combines the individual detectors into a single report, computes a risk
score, and walks files/directories for batch audits.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import core, data, detect

__all__ = ["AuditReport", "audit_text", "audit_file", "audit_path"]


SEVERITY_WEIGHT = {
    "critical": 25,
    "warning": 8,
    "info": 1,
}
SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


@dataclass
class AuditReport:
    """Result of an audit over one target."""

    target: str
    score: int
    findings: List[detect.Finding] = field(default_factory=list)
    stats: Dict[str, object] = field(default_factory=dict)

    @property
    def critical(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def warning(self) -> int:
        return sum(1 for f in self.findings if f.severity == "warning")

    @property
    def info(self) -> int:
        return sum(1 for f in self.findings if f.severity == "info")

    def exit_code(self, fail_on: str = "critical") -> int:
        if self.critical > 0 and fail_on in ("critical", "warning", "info"):
            return 2
        if self.warning > 0 and fail_on in ("warning", "info"):
            return 1
        if self.info > 0 and fail_on == "info":
            return 1
        return 0

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "score": self.score,
            "summary": {
                "critical": self.critical,
                "warning": self.warning,
                "info": self.info,
            },
            "stats": self.stats,
            "findings": [f.as_dict() for f in self.findings],
        }


def _compute_score(findings: List[detect.Finding]) -> int:
    penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    return max(0, 100 - penalty)


def audit_text(text: str, target: str = "<text>") -> AuditReport:
    """Audit an in-memory string."""
    findings: List[detect.Finding] = []
    findings += detect.find_invisibles(text)
    findings += detect.find_control(text)
    findings += detect.find_confusables(text)
    findings += detect.find_mixed_scripts(text)
    findings += detect.find_non_normalized(text)

    findings.sort(
        key=lambda f: (f.index, SEVERITY_ORDER.get(f.severity, 9))
    )

    scripts: Dict[str, int] = {}
    non_ascii = 0
    for ch in text:
        if not ch.isascii():
            non_ascii += 1
            scripts[core.script_of(ch)] = scripts.get(core.script_of(ch), 0) + 1

    stats = {
        "chars": len(text),
        "lines": text.count("\n") + 1 if text else 0,
        "non_ascii": non_ascii,
        "scripts": dict(
            sorted(scripts.items(), key=lambda kv: kv[1], reverse=True)[:8]
        ),
    }
    return AuditReport(
        target=target,
        score=_compute_score(findings),
        findings=findings,
        stats=stats,
    )


def audit_file(path: str, max_size: int = 5 * 1024 * 1024) -> AuditReport:
    """Audit a single file on disk."""
    if not os.path.isfile(path):
        return AuditReport(target=path, score=100, findings=[], stats={})
    size = os.path.getsize(path)
    if size > max_size:
        return AuditReport(
            target=path,
            score=100,
            findings=[
                detect.Finding(
                    kind="skip",
                    severity="info",
                    line=0,
                    col=0,
                    index=0,
                    char=None,
                    codepoint="",
                    name="skipped",
                    message="file too large (%d bytes), skipped" % size,
                    context="",
                    suggestion="",
                )
            ],
            stats={"size": size},
        )

    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return AuditReport(
            target=path,
            score=100,
            findings=[
                detect.Finding(
                    kind="error",
                    severity="warning",
                    line=0,
                    col=0,
                    index=0,
                    char=None,
                    codepoint="",
                    name="read error",
                    message="could not read file: %s" % exc,
                    context="",
                    suggestion="",
                )
            ],
            stats={},
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Re-decode with replacement but flag the decoding problem.
        text = raw.decode("utf-8", errors="replace")
        report = audit_text(text, target=path)
        report.findings.insert(
            0,
            detect.Finding(
                kind="encoding",
                severity="warning",
                line=1,
                col=1,
                index=0,
                char=None,
                codepoint="",
                name="invalid utf-8",
                message="file is not valid UTF-8 — decoded with replacement",
                context="",
                suggestion="re-save the file as UTF-8",
            ),
        )
        report.score = _compute_score(report.findings)
        return report

    report = audit_text(text, target=path)
    return report


def audit_path(
    root: str,
    recursive: bool = False,
    extensions: Optional[set] = None,
    skip_dirs: Optional[set] = None,
    max_findings: int = 200,
) -> Dict[str, AuditReport]:
    """Audit a path (file or directory) and return a map of reports."""
    extensions = extensions if extensions is not None else data.TEXT_EXTENSIONS
    skip_dirs = skip_dirs if skip_dirs is not None else data.DEFAULT_SKIP_DIRS

    if os.path.isfile(root):
        return {root: audit_file(root)}

    reports: Dict[str, AuditReport] = {}
    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in extensions:
                    full = os.path.join(dirpath, fn)
                    rep = audit_file(full)
                    if rep.findings:
                        reports[full] = rep
    else:
        for fn in os.listdir(root):
            full = os.path.join(root, fn)
            if os.path.isfile(full):
                if os.path.splitext(fn)[1].lower() in extensions:
                    rep = audit_file(full)
                    if rep.findings:
                        reports[full] = rep
    return reports
