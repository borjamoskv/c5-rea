# AGENTS.md — C5-REA Normative Contract

## 1. Binary Validation Commands (Zero-Waste Gate)
- **Unit & Parity Test Suite (runtime depends on selected tests and host):**
  `python3 -m unittest discover -s tests -p "test_*.py" -v`
- **Existence-Gap Self-Audit (0% Slop / 0% Phantom Imports):**
  `python3 c5_rea_cli.py existence-gap .`

## 2. Repository Invariants
- **Zero External Dependencies:** All core modules (`evidence_schema.py`, `rea_orchestrator.py`, `rea_unpacker.py`, `rea_decompiler.py`, `rea_recreator.py`, `rea_auditor.py`, `existence_gate.py`, `rea_mcp_server.py`) MUST rely exclusively on the Python 3.9+ Standard Library. Adding third-party PyPI packages (`pydantic`, `requests`, `numpy`, etc.) is strictly forbidden.
- **Kolmogorov Envelope Limit:** Extracted evidence envelopes (`EvidenceEnvelopeV2`) must compress structural symbols, IPC contracts, and CFG call graphs without dumping raw binary blobs or unpruned ASTs.
- **Verification verdicts:** Contract-only TypeScript/Rust channel diagnostics return `INCOMPLETE` even at 100% channel-name coverage, and `FAIL` when channels are missing. A Python contract without an executable behavior specification is also `INCOMPLETE`. Reserve `PASS` for supported executable backends with live differential verification against the pinned original; channel names alone never establish behavioral parity. Run `c5-rea existence-gap` separately and require its own `PASS` verdict with 0 violations; that verdict does not certify behavior.
- **Capability dependencies:** Zero external Python package dependencies applies to the stdlib core, not every external executable or generated artifact. JavaScript recovery requires caller-provided Node.js plus `@babel/parser`, `@babel/generator` and `@babel/types` in an explicit toolchain with `package-lock.json`; native lifting requires clang and backend-specific platform tools. Generated Rust contracts use serde. Document these per capability; do not install or assume them implicitly.

## 3. Exploration Restrictions
- Confine all inspections and edits strictly to the root modules and `tests/`. Do not traverse external directories or dump raw `.asar` contents into git-tracked folders.
