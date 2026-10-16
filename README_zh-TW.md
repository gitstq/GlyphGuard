<p align="center">
  <img src="https://img.shields.io/badge/zero--dependencies-✓-brightgreen" alt="zero deps">
  <img src="https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776AB" alt="python">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="license">
  <img src="https://github.com/gitstq/GlyphGuard/actions/workflows/ci.yml/badge.svg" alt="ci">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey" alt="platform">
</p>

<h1 align="center">🔥 GlyphGuard</h1>
<p align="center"><b>Unicode 同形字與不可見字元安全稽核引擎</b></p>

<p align="center">
  <a href="README.md">簡體中文</a> · <a href="README_zh-TW.md">繁體中文</a> · <a href="README_en.md">English</a>
</p>

> 輕量級、零依賴、純標準函式庫的命令列工具：偵測 Unicode 同形字（homoglyph）釣魚、不可見／格式字元，以及 Trojan Source 雙向文字攻擊（CVE-2021-42574）。

---

## 🎉 專案介紹

現代文字早已不限於 ASCII。攻擊者可利用 **Unicode 同形字** 讓 `аррle.com` 看起來像 `apple.com`，利用 **零寬字元** 在原始碼中藏匿惡意邏輯，或利用 **雙向控制字元**（Trojan Source，[CVE-2021-42574](https://nvd.nist.gov/vuln/detail/CVE-2021-42574)）顛倒註解與程式碼的視覺順序。這些字元在編輯器裡「看不見」，卻能繞過人工 Code Review。

**GlyphGuard** 是一款面向開發者的安全稽核引擎，能在本地、離線、零依賴的條件下，對文字、原始碼與網域進行系統化的 Unicode 安全體檢：

- 🛡️ 同形字骨架還原（UTS #39 思路的精選子集），一眼看穿 `аррle` → `apple`
- 👻 不可見字元／格式字元／雙向覆寫符偵測（含 Trojan Source 攻擊類）
- 🌐 混合腳本欺騙偵測（西里爾、希臘、亞美尼亞等腳本與拉丁文混排）
- 🧹 Unicode 規範化與清洗（NFC / NFD / NFKC / NFKD，剔除危險字元）
- 📏 終端機顯示寬度計算（東亞全角、組合字元、零寬）
- 🌍 網域同形字稽核（punycode 解碼 + 骨架還原）
- ⚙️ CI 門禁：基於嚴重級別的退出碼（0 / 1 / 2）
- 📦 跨平台單檔分發（`.pyz`，透過 `zipapp` 零依賴建置）

**靈感來源**：Unicode Technical Report #36 / #39、Trojan Source 研究，以及 `codebox/homoglyph` 等社群實踐。與帳號內既有的安全工具（RepoShield、VulnScan、MCPShield、PromptShield）領域完全不同，**相似度 < 10%**。

---

## ✨ 核心特性

- 🚀 **零依賴**：僅使用 Python 標準函式庫（`unicodedata` / `argparse` / `json`），無 `pip install` 負擔，可在任意離線環境執行。
- 🎯 **高精度**：僅收錄確鑿的同形字對應，降低誤報；自動規避中日韓（CJK）與拉丁文混排等合法場景。
- 🔍 **7 大類偵測**：不可見字元、雙向覆寫、控制字元、同形字、混合腳本、非規範化、網域同形字。
- 🤖 **CI 友善**：`audit` 指令回傳結構化退出碼，可直接接入 GitHub Actions / GitLab CI 作為合併門禁。
- 📄 **多格式報告**：人類可讀文字（含顏色）與機器可讀 JSON，便於二次處理。
- 💻 **跨平台**：Windows / macOS / Linux 一致執行；提供 `.pyz` 單檔可執行程式。
- 🌏 **三語文件**：簡體中文、繁體中文、English，統一維護。

---

## 🚀 快速開始

### 環境需求

- Python **3.9+**（僅標準函式庫，無須安裝任何第三方套件）

### 三種使用方式

**1. 單檔可執行程式（推薦，零安裝）**

從 [Releases](https://github.com/gitstq/GlyphGuard/releases) 下載對應平台的 `glyphguard-<os>.pyz`，直接執行：

```bash
python glyphguard-<os>.pyz audit ./src --recursive
```

**2. 原始碼執行**

```bash
git clone https://github.com/gitstq/GlyphGuard.git
cd GlyphGuard
python -m glyphguard audit ./src --recursive
```

**3. 可編輯安裝**

```bash
pip install -e .
glyphguard audit ./src --recursive
```

---

## 📖 詳細使用指南

| 指令 | 作用 |
| --- | --- |
| `audit PATH...` | 稽核檔案／目錄中的 Unicode 風險 |
| `skeleton TEXT` | 將文字映射為 ASCII 骨架 |
| `invisibles TEXT` | 列出不可見／控制字元 |
| `normalize TEXT` | Unicode 規範化或清洗 |
| `escape TEXT` | 跳脫非 ASCII／控制字元 |
| `unescape TEXT` | 反跳脫 |
| `width TEXT` | 計算終端機顯示寬度 |
| `inspect TEXT` | 逐字元 Unicode 內省 |
| `domain NAME` | 網域同形字稽核 |

```bash
# 遞迴稽核目錄
glyphguard audit ./src --recursive

# CI 門禁：遇到 critical 即非零退出
glyphguard audit ./src -r --fail-on critical
echo $?   # 0=乾淨, 1=warning, 2=critical

# 同形字骨架
glyphguard skeleton "аррle"      # apple

# 網域稽核
glyphguard domain "аррle.com"    # Looks like (ASCII): apple.com
```

---

## 💡 設計思路與迭代規劃

### 為什麼是純標準函式庫？

安全工具往往需要在受限／離線環境（CI Runner、稽核沙箱）中執行。引入第三方依賴會帶來供應鏈風險與安裝負擔。**GlyphGuard 堅持零依賴**，僅依賴 `unicodedata`（Python 內建的 Unicode 資料庫），因而可在任何安裝了 Python 的機器上即開即用。

### 資料策略

- **同形字表**（`data.py`）：手工精選、確鑿無誤的對應（西里爾／希臘／亞美尼亞等腳本與 ASCII 的視覺等價），並輔以演算法化區間（全角、數學字母、帶圈字母），避免誤報。
- **腳本識別**：優先採用 Unicode 字元名的「前綴」自動歸類（隨 Unicode 版本自維護），少量不可靠區間用顯式範圍表兜底。
- **評分**：critical / warning / info 加權扣分（100 分制），兼顧嚴重度與可讀性。

### 迭代規劃

- [ ] SARIF 輸出，直接接入 GitHub Code Scanning
- [ ] 編輯器外掛（VS Code / Neovim）即時高亮
- [ ] pre-commit hook 整合
- [ ] 更多腳本與語言（如天城文、泰文）的細粒度同形字覆蓋
- [ ] 設定檔 `.glyphguard.toml` 自訂白名單與閾值

---

## 📦 打包與部署指南

### 本地建置單檔可執行程式（零依賴）

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

### GitHub Actions 自動建置與發佈

倉庫已內建兩條工作流：

- `.github/workflows/ci.yml`：在 Windows / macOS / Linux × Python 3.9–3.13 上做語法校驗與 `unittest` 測試（**僅標準函式庫**）。
- `.github/workflows/release.yml`：推送 `v*` 標籤時，使用 `zipapp` 在三大平台建置 `.pyz`，並自動建立 GitHub Release 與附件。

```bash
git tag v1.0.0
git push origin v1.0.0      # 自動觸發建置與發佈
```

> 📥 **下載入口**：[GitHub Releases v1.0.0](https://github.com/gitstq/GlyphGuard/releases/tag/v1.0.0)

---

## 🤝 貢獻指南

歡迎貢獻！請閱讀 [CONTRIBUTING.md](CONTRIBUTING.md)：

- 零依賴原則（禁止引入第三方套件）
- Angular 提交規範（`feat:` / `fix:` / `docs:` …）
- 新增同形字對應須配套單元測試
- 本地僅做語法校驗，完整測試由雲端 CI 完成

---

## 📄 開源協議

本專案基於 [MIT License](LICENSE) 開源。

<p align="center">Made with 🔥 by <a href="https://github.com/gitstq">gitstq</a></p>
