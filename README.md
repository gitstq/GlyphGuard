<p align="center">
  <img src="https://img.shields.io/badge/zero--dependencies-✓-brightgreen" alt="zero deps">
  <img src="https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776AB" alt="python">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="license">
  <img src="https://github.com/gitstq/GlyphGuard/actions/workflows/ci.yml/badge.svg" alt="ci">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey" alt="platform">
</p>

<h1 align="center">🔥 GlyphGuard</h1>
<p align="center"><b>Unicode 同形字与不可见字符安全审计引擎</b></p>

<p align="center">
  <a href="README.md">简体中文</a> · <a href="README_zh-TW.md">繁體中文</a> · <a href="README_en.md">English</a>
</p>

> 轻量级、零依赖、纯标准库的命令行工具：检测 Unicode 同形字（homoglyph）钓鱼、不可见/格式字符、以及 Trojan Source 双向文本攻击（CVE-2021-42574）。

---

## 🎉 项目介绍

现代文本不再只是 ASCII。攻击者可以利用 **Unicode 同形字** 让 `аррle.com` 看起来像 `apple.com`，利用 **零宽字符** 在源码里藏匿恶意逻辑，利用 **双向控制字符**（Trojan Source，[CVE-2021-42574](https://nvd.nist.gov/vuln/detail/CVE-2021-42574)）颠倒注释与代码的视觉顺序。这些字符在编辑器中「看不见」，却能绕过人工 Code Review。

**GlyphGuard** 是一款面向开发者的安全审计引擎，能在本地、离线、零依赖的条件下，对文本、源码与域名进行系统化的 Unicode 安全体检：

- 🛡️ 同源形字骨架还原（UTS #39 思路的精选子集），一眼看穿 `аррle` → `apple`
- 👻 不可见字符 / 格式字符 / 双向覆写符检测（含 Trojan Source 攻击类）
- 🌐 混合脚本欺骗检测（西里尔、希腊、亚美尼亚等脚本与拉丁文混排）
- 🧹 Unicode 规范化与清洗（NFC / NFD / NFKC / NFKD，剔除危险字符）
- 📏 终端显示宽度计算（东亚全角、组合字符、零宽）
- 🌍 域名同形字审计（punycode 解码 + 骨架还原）
- ⚙️ CI 门禁：基于严重级别的退出码（0 / 1 / 2）
- 📦 跨平台单文件分发（`.pyz`，通过 `zipapp` 零依赖构建）

**灵感来源**：Unicode Technical Report #36 / #39、Trojan Source 研究、以及 `codebox/homoglyph` 等社区实践。与账号内已有的安全工具（RepoShield、VulnScan、MCPShield、PromptShield）领域完全不同，**相似度 < 10%**。

---

## ✨ 核心特性

- 🚀 **零依赖**：仅使用 Python 标准库（`unicodedata` / `argparse` / `json`），无 `pip install` 负担，可在任意离线环境运行。
- 🎯 **高精度**：仅收录确凿的同形字映射，降低误报；自动规避中日韩（CJK）与拉丁文混排等合法场景。
- 🔍 **7 大类检测**：不可见字符、双向覆写、控制字符、同形字、混合脚本、非规范化、域名同形字。
- 🤖 **CI 友好**：`audit` 命令返回结构化退出码，可直接接入 GitHub Actions / GitLab CI 作为合并门禁。
- 📄 **多格式报告**：人类可读文本（含颜色）与机器可读 JSON，便于二次处理。
- 💻 **跨平台**：Windows / macOS / Linux 一致运行；提供 `.pyz` 单文件可执行程序。
- 🌏 **三语文档**：简体中文、繁體中文、English，统一维护。

---

## 🚀 快速开始

### 环境要求

- Python **3.9+**（仅标准库，无需安装任何第三方包）

### 三种使用方式

**1. 单文件可执行程序（推荐，零安装）**

从 [Releases](https://github.com/gitstq/GlyphGuard/releases) 下载对应平台的 `glyphguard-<os>.pyz`，直接运行：

```bash
python glyphguard-<os>.pyz audit ./src --recursive
```

**2. 源码运行**

```bash
git clone https://github.com/gitstq/GlyphGuard.git
cd GlyphGuard
python -m glyphguard audit ./src --recursive
```

**3. 可编辑安装**

```bash
pip install -e .
glyphguard audit ./src --recursive
```

---

## 📖 详细使用指南

### 命令一览

| 命令 | 作用 |
| --- | --- |
| `audit PATH...` | 审计文件 / 目录中的 Unicode 风险 |
| `skeleton TEXT` | 将文本映射为 ASCII 骨架 |
| `invisibles TEXT` | 列出不可见 / 控制字符 |
| `normalize TEXT` | Unicode 规范化或清洗 |
| `escape TEXT` | 转义非 ASCII / 控制字符 |
| `unescape TEXT` | 反转义 |
| `width TEXT` | 计算终端显示宽度 |
| `inspect TEXT` | 逐字符 Unicode 内省 |
| `domain NAME` | 域名同形字审计 |

### `audit` —— 文件 / 目录审计

```bash
# 审计单个文件
glyphguard audit suspicious.py

# 递归审计目录（仅扫描代码/文本类扩展名）
glyphguard audit ./src --recursive

# 自定义扩展名、排除目录、JSON 输出
glyphguard audit ./src -r --ext .py,.js,.ts --exclude-dir node_modules --format json

# CI 门禁：遇到 critical 即非零退出
glyphguard audit ./src -r --fail-on critical
echo $?   # 0=干净, 1=warning, 2=critical
```

示例输出：

```
GlyphGuard v1.0.0 — Unicode Security Audit
Target: login.py
Score: 72/100  (2 critical, 1 warning, 0 info)
──────────────────────────────────────────────────
[CRITICAL] L12:C8  U+202E RIGHT-TO-LEFT OVERRIDE (bidi)
   bidirectional override can reorder surrounding text
   ctx: password = "user"; // ‮admin
   fix: remove the override or balance it with a matching pop
```

### `skeleton` —— 同形字骨架

```bash
glyphguard skeleton "аррle"
# apple
```

骨架还原让「看起来像什么」一目了然，是识别钓鱼域名的利器。

### `invisibles` —— 不可见字符清单

```bash
glyphguard invisibles "a​b"        # 0x200B 零宽空格会被列出
glyphguard invisibles ./note.md --format json
```

### `normalize` / `clean` —— 规范化与清洗

```bash
glyphguard normalize "café" --form NFC          # 规范化为预组合形式
glyphguard normalize ./evil.py --clean --in-place ./clean.py   # 剔除危险字符
```

### `inspect` —— 逐字符内省

```bash
glyphguard inspect "a中\u200bb"
# idx  cp       char        name                        cat    w   script
# 0    U+0061   a           LATIN SMALL LETTER A        Ll     1   Latin
# 1    U+4E2D   中           CJK UNIFIED IDEOGRAPH-...   Lo     2   Han
# 2    U+200B   <U+200B>     ZERO WIDTH SPACE           Cf     0   Inherited
```

### `domain` —— 域名同形字审计

```bash
glyphguard domain "аррle.com"
# Looks like (ASCII): apple.com
# 同时列出 critical 级别的同形字发现
```

---

## 💡 设计思路与迭代规划

### 为什么是纯标准库？

安全工具往往需要在受限 / 离线环境（CI Runner、审计沙箱）中运行。引入第三方依赖会带来供应链风险与安装负担。**GlyphGuard 坚持零依赖**，仅依赖 `unicodedata`（Python 内置的 Unicode 数据库），因而可在任何装有 Python 的机器上即开即用。

### 数据策略

- **同形字表**（`data.py`）：手工精选、确凿无误的映射（西里尔 / 希腊 / 亚美尼亚等脚本与 ASCII 的视觉等价），并辅以算法化区间（全角、数学字母、带圈字母），避免误报。
- **脚本识别**：优先采用 Unicode 字符名的「前缀」自动归类（随 Unicode 版本自维护），少量不可靠区间用显式范围表兜底。
- **评分**：critical / warning / info 加权扣分（100 分制），兼顾严重度与可读性。

### 迭代规划

- [ ] SARIF 输出，直接接入 GitHub Code Scanning
- [ ] 编辑器插件（VS Code / Neovim）实时高亮
- [ ] pre-commit hook 集成
- [ ] 更多脚本与语言（如天城文、泰文）的细粒度同形字覆盖
- [ ] 配置文件 `.glyphguard.toml` 自定义白名单与阈值

---

## 📦 打包与部署指南

### 本地构建单文件可执行程序（零依赖）

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

### GitHub Actions 自动构建与发布

仓库已内置两条工作流：

- `.github/workflows/ci.yml`：在 Windows / macOS / Linux × Python 3.9–3.13 上做语法校验与 `unittest` 测试（**仅标准库**）。
- `.github/workflows/release.yml`：打 `v*` 标签时，使用 `zipapp` 在三大平台构建 `.pyz`，并自动创建 GitHub Release 与附件。

```bash
git tag v1.0.0
git push origin v1.0.0      # 自动触发构建与发布
```

> 📥 **下载入口**：[GitHub Releases v1.0.0](https://github.com/gitstq/GlyphGuard/releases/tag/v1.0.0)

---

## 🤝 贡献指南

欢迎贡献！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)：

- 零依赖原则（禁止引入第三方包）
- Angular 提交规范（`feat:` / `fix:` / `docs:` …）
- 新增同形字映射须配套单元测试
- 本地仅做语法校验，完整测试由云端 CI 完成

---

## 📄 开源协议

本项目基于 [MIT License](LICENSE) 开源。

<p align="center">Made with 🔥 by <a href="https://github.com/gitstq">gitstq</a></p>
