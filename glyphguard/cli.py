"""Command-line interface for GlyphGuard."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import audit, core, detect, report
from .__init__ import __version__


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

class _Parser(argparse.ArgumentParser):
    """ArgumentParser that exits with code 3 on usage errors."""

    def error(self, message: str) -> None:  # pragma: no cover - trivial
        sys.stderr.write("error: %s\n" % message)
        raise SystemExit(3)


def _build_parser() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "--no-color", action="store_true", help="disable ANSI colors"
    )

    parser = _Parser(
        prog="glyphguard",
        description="Unicode homoglyph & invisible-character security audit engine",
    )
    parser.add_argument(
        "--version", action="version", version="GlyphGuard %s" % __version__
    )
    sub = parser.add_subparsers(dest="command")

    p_audit = sub.add_parser(
        "audit", parents=[parent], help="audit files/directories for Unicode risks"
    )
    p_audit.add_argument("paths", nargs="+", help="files or directories")
    p_audit.add_argument("-r", "--recursive", action="store_true")
    p_audit.add_argument(
        "--ext", default=None,
        help="comma-separated extensions to scan (e.g. .py,.js)",
    )
    p_audit.add_argument(
        "--exclude-dir", action="append", default=[],
        help="directory name to skip (repeatable)",
    )
    p_audit.add_argument(
        "--format", choices=["text", "json"], default="text"
    )
    p_audit.add_argument(
        "--fail-on",
        choices=["critical", "warning", "info", "never"],
        default="critical",
    )
    p_audit.add_argument("--max-findings", type=int, default=200)

    p_skel = sub.add_parser(
        "skeleton", parents=[parent], help="map text to its ASCII skeleton"
    )
    p_skel.add_argument("text", help="text or - (stdin)")

    p_inv = sub.add_parser(
        "invisibles", parents=[parent], help="list invisible/control characters"
    )
    p_inv.add_argument("text", help="file path, text or - (stdin)")
    p_inv.add_argument("--format", choices=["text", "json"], default="text")

    p_norm = sub.add_parser(
        "normalize", parents=[parent], help="normalize / clean Unicode text"
    )
    p_norm.add_argument("text", help="file path, text or - (stdin)")
    p_norm.add_argument(
        "--form", choices=["NFC", "NFD", "NFKC", "NFKD"], default="NFC"
    )
    p_norm.add_argument("--clean", action="store_true",
                        help="also strip invisible/format characters")
    p_norm.add_argument("--in-place", default=None,
                        help="write output to this file")

    p_esc = sub.add_parser(
        "escape", parents=[parent], help="escape non-ASCII / control characters"
    )
    p_esc.add_argument("text", help="file path, text or - (stdin)")
    p_esc.add_argument(
        "--style", choices=["unicode", "html", "name"], default="unicode"
    )

    p_unesc = sub.add_parser(
        "unescape", parents=[parent], help="reverse escape_text"
    )
    p_unesc.add_argument("text", help="file path, text or - (stdin)")

    p_w = sub.add_parser(
        "width", parents=[parent], help="terminal display width of text"
    )
    p_w.add_argument("text", help="file path, text or - (stdin)")

    p_insp = sub.add_parser(
        "inspect", parents=[parent], help="per-character Unicode introspection"
    )
    p_insp.add_argument("text", help="file path, text or - (stdin)")

    p_dom = sub.add_parser(
        "domain", parents=[parent], help="audit a domain for homograph attacks"
    )
    p_dom.add_argument("name", help="domain name")
    p_dom.add_argument("--format", choices=["text", "json"], default="text")

    p_ver = sub.add_parser(
        "version", parents=[parent], help="show the GlyphGuard version"
    )

    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _color_enabled(no_color: bool) -> bool:
    if no_color:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _resolve_text(arg: str) -> str:
    if arg == "-":
        return sys.stdin.read()
    if os.path.isfile(arg):
        with open(arg, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return arg


def _trim(report: audit.AuditReport, limit: int) -> audit.AuditReport:
    if limit and len(report.findings) > limit:
        extra = len(report.findings) - limit
        report.findings = report.findings[:limit]
        report.findings.append(
            detect.Finding(
                kind="truncated", severity="info", line=0, col=0, index=0,
                char=None, codepoint="", name="truncated",
                message="%d more findings omitted (--max-findings %d)"
                % (extra, limit),
                context="", suggestion="",
            )
        )
    return report


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_audit(args: argparse.Namespace, color: report.Color) -> int:
    extensions = None
    if args.ext:
        extensions = {e.strip().lower() for e in args.ext.split(",") if e.strip()}

    from . import data as _data  # local import avoids cycle at module load
    skip_dirs = set(_data.DEFAULT_SKIP_DIRS) | set(args.exclude_dir)

    reports: dict = {}
    for path in args.paths:
        reports.update(
            audit.audit_path(
                path,
                recursive=args.recursive,
                extensions=extensions,
                skip_dirs=skip_dirs,
                max_findings=args.max_findings,
            )
        )
    for target in list(reports.keys()):
        _trim(reports[target], args.max_findings)

    if args.format == "json":
        print(report.format_reports_json(reports))
    else:
        print(report.format_reports(reports, color))

    worst = 0
    for rep in reports.values():
        code = rep.exit_code(args.fail_on)
        worst = max(worst, code)
    return worst


def cmd_skeleton(args: argparse.Namespace, color: report.Color) -> int:
    text = _resolve_text(args.text)
    print(core.skeleton(text))
    return 0


def cmd_invisibles(args: argparse.Namespace, color: report.Color) -> int:
    text = _resolve_text(args.text)
    findings = detect.find_invisibles(text) + detect.find_control(text)
    rep = audit.AuditReport(
        target="<input>",
        score=max(0, 100 - sum(audit.SEVERITY_WEIGHT[f.severity] for f in findings)),
        findings=findings,
        stats={"chars": len(text)},
    )
    if args.format == "json":
        print(report.format_json(rep))
    else:
        print(report.format_report(rep, color))
    return rep.exit_code("critical")


def cmd_normalize(args: argparse.Namespace, color: report.Color) -> int:
    text = _resolve_text(args.text)
    if args.clean:
        out = core.clean_text(text)
    else:
        out = core.normalize_text(text, args.form)
    if args.in_place:
        with open(args.in_place, "w", encoding="utf-8", newline="") as fh:
            fh.write(out)
        print("written: %s" % args.in_place)
    else:
        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")
    return 0


def cmd_escape(args: argparse.Namespace, color: report.Color) -> int:
    text = _resolve_text(args.text)
    print(core.escape_text(text, args.style))
    return 0


def cmd_unescape(args: argparse.Namespace, color: report.Color) -> int:
    text = _resolve_text(args.text)
    print(core.unescape_text(text))
    return 0


def cmd_width(args: argparse.Namespace, color: report.Color) -> int:
    text = _resolve_text(args.text)
    width = core.display_width(text)
    print("Width: %d" % width)
    return 0


def cmd_inspect(args: argparse.Namespace, color: report.Color) -> int:
    text = _resolve_text(args.text)
    print(report.format_inspect(text, color))
    return 0


def cmd_version(args: argparse.Namespace, color: report.Color) -> int:
    print("GlyphGuard v%s" % __version__)
    return 0


def cmd_domain(args: argparse.Namespace, color: report.Color) -> int:
    skeleton, findings = detect.check_domain(args.name)
    score = max(0, 100 - sum(audit.SEVERITY_WEIGHT[f.severity] for f in findings))
    rep = audit.AuditReport(
        target=args.name,
        score=score,
        findings=findings,
        stats={"skeleton": skeleton},
    )
    if args.format == "json":
        print(report.format_json(rep))
    else:
        print(report.format_report(rep, color))
        print(color.dim("Looks like (ASCII): %s" % skeleton))
    return rep.exit_code("critical")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_HANDLERS = {
    "audit": cmd_audit,
    "skeleton": cmd_skeleton,
    "invisibles": cmd_invisibles,
    "normalize": cmd_normalize,
    "escape": cmd_escape,
    "unescape": cmd_unescape,
    "width": cmd_width,
    "inspect": cmd_inspect,
    "domain": cmd_domain,
    "version": cmd_version,
}


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 3
    color = report.Color(_color_enabled(args.no_color))
    handler = _HANDLERS.get(args.command)
    if handler is None:  # pragma: no cover
        parser.print_help()
        return 3
    return handler(args, color)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
