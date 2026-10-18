# AGENTS.md — C5-REA Normative Contract

## 1. Binary Validation Commands (Zero-Waste Gate)
- **Unit & Parity Test Suite (< 0.01s):**
  `python3 -m unittest discover -s tests -p "test_*.py" -v`
- **Existence-Gap Self-Audit (0% Slop / 0% Phantom Imports):**
  `python3 c5_rea_cli.py existence-gap .`

## 2. Repository Invariants
- **Zero External Dependencies:** All core modules (`evidence_schema.py`, `rea_orchestrator.py`, `rea_unpacker.py`, `rea_decompiler.py`, `rea_recreator.py`, `rea_auditor.py`, `existence_gate.py`, `rea_mcp_server.py`) MUST rely exclusively on the Python 3.9+ Standard Library. Adding third-party PyPI packages (`pydantic`, `requests`, `numpy`, etc.) is strictly forbidden.
- **Kolmogorov Envelope Limit:** Extracted evidence envelopes (`EvidenceEnvelopeV2`) must compress structural symbols, IPC contracts, and CFG call graphs without dumping raw binary blobs or unpruned ASTs.
- **Popperian Falsification:** Every synthesized contract (`.ts`, `.rs`, `.py`) must pass both `c5-rea audit` (100% IPC channel parity) and `c5-rea existence-gap` (`PASS` verdict with 0 violations).

## 3. Exploration Restrictions
- Confine all inspections and edits strictly to the root modules and `tests/`. Do not traverse external directories or dump raw `.asar` contents into git-tracked folders.
