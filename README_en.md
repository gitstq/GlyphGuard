<p align="center">
  <img src="https://img.shields.io/badge/zero--dependencies-✓-brightgreen" alt="zero deps">
  <img src="https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776AB" alt="python">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="license">
  <img src="https://github.com/gitstq/GlyphGuard/actions/workflows/ci.yml/badge.svg" alt="ci">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey" alt="platform">
</p>

<h1 align="center">🔥 GlyphGuard</h1>
<p align="center"><b>Unicode Homoglyph &amp; Invisible-Character Security Audit Engine</b></p>

<p align="center">
  <a href="README.md">简体中文</a> · <a href="README_zh-TW.md">繁體中文</a> · <a href="README_en.md">English</a>
</p>

> A lightweight, zero-dependency, pure-stdlib CLI: detects Unicode homoglyph phishing, invisible/format characters, and Trojan Source bidirectional attacks (CVE-2021-42574).

---

## 🎉 Introduction

Modern text is no longer just ASCII. Attackers can use **Unicode homoglyphs** to make `аррle.com` look like `apple.com`, **zero-width characters** to smuggle malicious logic into source code, or **bidirectional control characters** (Trojan Source, [CVE-2021-42574](https://nvd.nist.gov/vuln/detail/CVE-2021-42574)) to visually reorder comments and code. These characters are invisible in editors yet bypass human code review.

**GlyphGuard** is a developer-facing security audit engine that performs a systematic Unicode health check on text, source code, and domain names — locally, offline, and dependency-free:

- 🛡️ Homoglyph skeleton mapping (a curated subset of the UTS #39 idea) — reveal `аррle` → `apple` at a glance
- 👻 Invisible / format / bidirectional-override detection (including the Trojan Source attack class)
- 🌐 Mixed-script spoofing detection (Cyrillic, Greek, Armenian, etc. mixed with Latin)
- 🧹 Unicode normalization & cleaning (NFC / NFD / NFKC / NFKD, stripping dangerous characters)
- 📏 Terminal display width (East-Asian wide, combining, zero-width)
- 🌍 Domain homograph audit (punycode decode + skeleton)
- ⚙️ CI gate: severity-based exit codes (0 / 1 / 2)
- 📦 Cross-platform single-file distribution (`.pyz` via `zipapp`, zero-dependency build)

**Inspiration**: Unicode Technical Reports #36 / #39, the Trojan Source research, and community work such as `codebox/homoglyph`. Distinct from the account's existing security tools (RepoShield, VulnScan, MCPShield, PromptShield) — **similarity < 10%**.

---

## ✨ Core Features

- 🚀 **Zero dependencies**: only the Python standard library (`unicodedata` / `argparse` / `json`) — no `pip install`, runs anywhere offline.
- 🎯 **High precision**: only well-established confusable mappings are included to reduce false positives; legitimate CJK+Latin mixes are automatically exempted.
- 🔍 **7 detection classes**: invisible chars, bidirectional overrides, control chars, confusables, mixed scripts, non-normalized text, domain homographs.
- 🤖 **CI friendly**: `audit` returns structured exit codes, ready to gate merges in GitHub Actions / GitLab CI.
- 📄 **Multi-format reports**: human-readable (colored) text and machine-readable JSON.
- 💻 **Cross-platform**: consistent on Windows / macOS / Linux; ships a `.pyz` single-file executable.
- 🌏 **Trilingual docs**: Simplified Chinese, Traditional Chinese, and English.

---

## 🚀 Quick Start

### Requirements

- Python **3.9+** (standard library only, no third-party packages)

### Three ways to use it

**1. Single-file executable (recommended, zero install)**

Download `glyphguard-<os>.pyz` for your platform from [Releases](https://github.com/gitstq/GlyphGuard/releases):

```bash
python glyphguard-<os>.pyz audit ./src --recursive
```

**2. Run from source**

```bash
git clone https://github.com/gitstq/GlyphGuard.git
cd GlyphGuard
python -m glyphguard audit ./src --recursive
```

**3. Editable install**

```bash
pip install -e .
glyphguard audit ./src --recursive
```

---

## 📖 Usage Guide

| Command | Purpose |
| --- | --- |
| `audit PATH...` | Audit files / directories for Unicode risks |
| `skeleton TEXT` | Map text to its ASCII skeleton |
| `invisibles TEXT` | List invisible / control characters |
| `normalize TEXT` | Unicode normalization or cleaning |
| `escape TEXT` | Escape non-ASCII / control characters |
| `unescape TEXT` | Reverse escape |
| `width TEXT` | Compute terminal display width |
| `inspect TEXT` | Per-character Unicode introspection |
| `domain NAME` | Audit a domain for homographs |

```bash
# Recursive directory audit
glyphguard audit ./src --recursive

# CI gate: non-zero exit on critical
glyphguard audit ./src -r --fail-on critical
echo $?   # 0=clean, 1=warning, 2=critical

# Homoglyph skeleton
glyphguard skeleton "аррle"      # apple

# Domain audit
glyphguard domain "аррle.com"    # Looks like (ASCII): apple.com
```

---

## 💡 Design & Roadmap

### Why pure standard library?

Security tools often run in constrained / offline environments (CI runners, audit sandboxes). Third-party dependencies introduce supply-chain risk and install overhead. **GlyphGuard is strictly zero-dependency**, relying only on `unicodedata` (Python's built-in Unicode database), so it runs on any machine with Python.

### Data strategy

- **Confusable table** (`data.py`): hand-curated, unambiguous mappings (Cyrillic / Greek / Armenian look-alikes of ASCII), augmented by algorithmic ranges (fullwidth, mathematical letters, circled letters) to avoid false positives.
- **Script detection**: Unicode character-name prefixes are used first (self-maintaining across Unicode versions), with an explicit range table only for unreliable cases.
- **Scoring**: critical / warning / info weighted deductions (100-point scale), balancing severity and readability.

### Roadmap

- [ ] SARIF output for GitHub Code Scanning
- [ ] Editor plugins (VS Code / Neovim) with live highlighting
- [ ] pre-commit hook integration
- [ ] Finer-grained homoglyph coverage for more scripts (Devanagari, Thai, …)
- [ ] `.glyphguard.toml` config for allowlists and thresholds

---

## 📦 Packaging & Deployment

### Build a single-file executable locally (zero-dependency)

```bash
python -m compileall -q glyphguard
python - <<'PY'
import shutil, zipapp
shutil.copytree("glyphguard", "stage/glyphguard")
zipapp.create_archive("stage", "dist/glyphguard.pyz",
                      main="glyphguard.cli:main",
                      interpreter="/usr/bin/env python3")
PY
python dist/glyphguard.pyz version
```

### GitHub Actions automated build & release

Two workflows are included:

- `.github/workflows/ci.yml`: syntax check + `unittest` on Windows / macOS / Linux × Python 3.9–3.13 (**stdlib only**).
- `.github/workflows/release.yml`: on `v*` tags, builds `.pyz` on all three platforms via `zipapp` and auto-creates the GitHub Release with assets.

```bash
git tag v1.0.0
git push origin v1.0.0      # triggers build & release
```

> 📥 **Download**: [GitHub Releases v1.0.0](https://github.com/gitstq/GlyphGuard/releases/tag/v1.0.0)

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md):

- Zero-dependency principle (no third-party packages)
- Angular commit convention (`feat:` / `fix:` / `docs:` …)
- New confusable mappings require unit tests
- Local syntax check only; full tests run in cloud CI

---

## 📄 License

Released under the [MIT License](LICENSE).

<p align="center">Made with 🔥 by <a href="https://github.com/gitstq">gitstq</a></p>
