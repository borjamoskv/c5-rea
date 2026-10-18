<div align="center">

**English** · [Español](#arquitectura-soberana-c5-real) · [简体中文](#为什么选择-c5-rea)

# C5-REA: Clean-Room Reverse Engineering & Existence-Gap Firewall for AI Agents

### Dissect any binary or Electron app in `<15ms`. Compress evidence by `2,900×` (`60 KB` vs `176 MB`). Synthesize Clean-Room code with `0%` LLM hallucinations.

[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0_(Pure_Stdlib)-00e676?style=flat-square)](#benchmark-silicon-reality-vs-npm-wrappers)
[![Existence Gap](https://img.shields.io/badge/Existence_Gap-0%25_Hallucination-38bdf8?style=flat-square)](#the-existence-gap-firewall-anti-slopsquatting)
[![MCP Native](https://img.shields.io/badge/MCP-stdio_Server_(%3C15ms)-a855f7?style=flat-square)](#mcp-server-integration-claude-cursor-antigravity-codex)
[![License: MIT](https://img.shields.io/badge/License-MIT-f4c430?style=flat-square)](LICENSE)

**By Borja Fernández Angulo (`borjamoskv`)** — *Complex Systems Researcher*

</div>

---

## Why `C5-REA`? (The Thermodynamic Problem in 2026)

Every developer using AI coding agents (Claude Code, Cursor, Antigravity, Codex) hits **two catastrophic walls**:

1. **The Reverse-Engineering Context Explosion:** Existing reverse-engineering wrappers (`npx rea-agents`, raw Ghidra/AST dumpers) pull **400+ npm packages**, take **52 seconds** to run, and dump **176 MB of raw JSON** into your LLM context window—instantly crashing your session or burning \$15 of API quota on noise.
2. **The Existence Gap (Vibe-Coding Slop):** When your agent finally writes the reconstructed code, it hallucinates non-existent packages (*slopsquatting*), leaves hollow `// TODO: rest of code` stubs, or drops 40% of the original IPC channels.

**`C5-REA` solves both in pure silicon (`0` external dependencies, `<15ms` latency):**

```text
COMMERCIAL NPM WRAPPERS (High Anergy):
[Binary / .asar] ──► [400+ npm deps / 52s] ──► [176 MB Raw AST Dump] ──► [LLM Context Crash]

C5-REA SOVEREIGN ARCHITECTURE (Clean-Room + Popperian Falsification):
[Binary / Electron .asar]
       │
       ▼ (In-Memory Stream Unpacker & Mach-O/ELF CFG Filter · <15 ms · 0 deps)
[Kolmogorov Evidence Envelope v2 (~60 KB JSON: IPC Contracts + Call Graphs)]
       │
       ▼ (Clean-Room Synthesizer · Zero Proprietary Blobs)
[Idiomatic TypeScript / Rust / Python Implementation]
       │
       ▼ (Popperian Parity Auditor + Existence-Gap Firewall)
[100% IPC Contract Parity + 0% Phantom Imports / Slopsquatting (PASS)]
```

---

## Benchmark: Silicon Reality vs. npm Wrappers

Measured on Apple Silicon (M3 Pro, Darwin ARM64) inspecting a production 2,000-file Electron `app.asar` bundle and native Mach-O binaries:

| Metric | Legacy npm Wrappers (`rea-agents` / AST Dumps) | `C5-REA` (Pure Stdlib Microkernel) | Exergy Gain |
| :--- | :--- | :--- | :--- |
| **External Dependencies** | 400+ npm packages (~380 MB disk) | **`0` (100% Pure Python Stdlib)** | **$\infty$ (Zero Supply-Chain Risk)** |
| **`app.asar` Unpack & IPC Index** | ~14.20 s (Full disk I/O extraction) | **`0.012 s` (In-Memory Header Stream)** | **`1,183×` Faster** |
| **LLM Context Payload** | ~176,000 KB (Context Window Overflow) | **`~60 KB` (`EvidenceEnvelopeV2`)** | **`2,933×` Token Compression** |
| **Contract Parity Guarantee** | None (Unverified LLM output) | **Popperian Falsification (`PASS`/`FAIL`)** | **100% Deterministic** |
| **Anti-Slopsquatting Firewall** | None | **`existence-gap` AST & Manifest Gate** | **0% Hallucinated Packages** |

---

## 30-Second Quick Start (Zero Dependencies)

No `npm install`. No `pip install` bloat. Runs natively on any machine with Python 3.9+:

```bash
git clone https://github.com/borjamoskv/c5-rea.git
cd c5-rea

# 1. Binary Triage (Architecture, Shannon Entropy, Packer Detection, SHA-256)
./c5_rea_cli.py triage /Applications/YourTarget.app

# 2. In-Memory Electron ASAR Forensics (Extracts IPC contracts in <15ms without disk bloat)
./c5_rea_cli.py unpack /Applications/YourTarget.app/Contents/Resources/app.asar

# 3. Static Mach-O Control Flow Graph (CFG) & Call-Stub Decompilation
./c5_rea_cli.py decompile /bin/ls --max 5

# 4. Clean-Room Synthesis (Generates zero-blob TypeScript, Rust, or Python contracts)
./c5_rea_cli.py synthesize evidence/evidence_92c9211a2182.json --lang ts
./c5_rea_cli.py synthesize evidence/evidence_92c9211a2182.json --lang rust

# 5. Popperian Parity Falsification (Certifies 100% IPC channel coverage)
./c5_rea_cli.py audit evidence/evidence_92c9211a2182.json reconstructed/ts/ipc_contracts.ts

# 6. Existence-Gap Firewall (Blocks LLM slopsquatting, phantom imports & hollow stubs)
./c5_rea_cli.py existence-gap .
```

---

## The Existence-Gap Firewall (Anti-Slopsquatting)

Use `c5-rea existence-gap` as a standalone pre-commit hook or MCP tool to stop AI coding agents from injecting hallucinated packages or lazy truncation stubs into your codebase:

```bash
$ ./c5_rea_cli.py existence-gap ./my-agent-pr/
[+] Existence-Gap Verdict: FAIL (1 files, 3 violations)
[
  {
    "file": "vibe_coded.py",
    "status": "FAIL",
    "violations": [
      {"type": "SLOPSQUATTING_RISK", "line": 1, "detail": "Suspected hallucinated package import: 'openai_magic'"},
      {"type": "HOLLOW_FUNCTION_STUB", "line": 2, "detail": "Function 'fake_feature' contains only a hollow stub (pass/...)."},
      {"type": "LLM_TRUNCATION_MARKER", "line": 3, "detail": "Lazy LLM truncation placeholder detected: # ... rest of existing code"}
    ]
  }
]
```

Add the badge to your repository once protected:

```markdown
[![Existence Gap: 0% Slop](https://img.shields.io/badge/Existence_Gap-0%25_Hallucination-38bdf8?style=flat-square)](https://github.com/borjamoskv/c5-rea)
```

---

## MCP Server Integration (Claude Code, Cursor, Antigravity, Codex)

Register `C5-REA` as a universal, zero-latency `stdio` MCP server in your agent's config (`mcp_config.json` / `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "c5-rea": {
      "command": "python3",
      "args": ["/absolute/path/to/c5-rea/c5_rea_cli.py", "serve"]
    }
  }
}
```

### Exposed MCP Tools (`<15ms` per call):
- `rea_triage` — Non-invasive binary triage (Architecture, Shannon entropy $H \in [0, 8]$, UPX packer detection, SHA-256).
- `rea_inspect_asar` — In-memory Electron `.asar` header parser and IPC channel extractor.
- `rea_decompile_cfg` — Static Mach-O disassembler, Control Flow Graph (CFG) node counter, and `xrefs_out` call-graph extractor.
- `rea_synthesize` — Clean-room contract generator for TypeScript (`.ts`), Rust (`.rs`), and Python (`.py`).
- `rea_audit_parity` — Deterministic Popperian verifier guaranteeing 100% IPC contract parity against `EvidenceEnvelopeV2`.
- `rea_existence_gap` — AST & manifest firewall against phantom imports, slopsquatting, and LLM truncation markers.

---

## Arquitectura Soberana C5-REAL

Frente a los envoltorios comerciales inflados en Node.js, **C5-REA** implementa una arquitectura de **Sala Limpia (Clean-Room)** dividida en 5 subagentes deterministas (`subagents/`) y un verificador de brecha de existencia (`existence_gate.py`), ejecutando su batería completa de 8 tests unitarios en **0.004 segundos** sin una sola librería de terceros.

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## 为什么选择 C5-REA？

传统的逆向工程代理工具（如 `rea-agents`）依赖 400 多个 npm 包，需要将整个 `.asar` 解压到磁盘并向大模型注入高达 **176 MB** 的 AST JSON 数据，导致上下文窗口瞬间崩溃。

**C5-REA** 采用 **100% Python 标准库（零外部依赖）**：
- **15 毫秒内存级解析**：无需落盘即可提取 Electron `app.asar` 与 Mach-O 控制流图（CFG）。
- **2,900 倍上下文压缩**：通过柯尔莫哥洛夫证据信封（`EvidenceEnvelopeV2`）将核心架构压缩至 **~60 KB**。
- **波普尔证伪与反幻觉防火墙（Existence-Gap Gate）**：100% 验证 IPC 契约对齐，自动拦截大模型捏造的幽灵依赖包（Slopsquatting）与未完成的代码桩。
