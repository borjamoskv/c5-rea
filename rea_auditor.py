#!/usr/bin/env python3
"""
Channel diagnostics and live functional verification.
Channel names alone can only produce INCOMPLETE or FAIL. PASS is reserved for
an independent executable tested against the pinned original process.
"""

import sys
import os
import json
import re
from pathlib import Path
from typing import Dict, Any, List

from evidence_schema import EvidenceEnvelopeV2


def audit_reconstruction(envelope, artifact, seed=None, manage_reference=False):
    """Only live differential execution may certify executable parity."""
    from rea_behavior import BACKEND, audit_behavior
    from rea_llm import BACKEND as NATIVE_BACKEND, audit_native
    from rea_chat import BACKEND as CHAT_BACKEND, audit_chat
    from rea_lift import BACKEND as BINARY_BACKEND, audit_binary
    from rea_javascript import verify_js_handlers_live
    spec = envelope.clean_room_specification
    if spec.get("backend") == BINARY_BACKEND:
        return audit_binary(envelope, artifact, seed=seed)
    if spec.get("backend") == CHAT_BACKEND:
        return audit_chat(envelope, artifact, seed=seed, manage_reference=manage_reference)
    if spec.get("backend") == NATIVE_BACKEND:
        return audit_native(envelope, artifact, seed=seed, manage_reference=manage_reference)
    if spec.get("backend") == BACKEND:
        return audit_behavior(envelope, artifact, seed=seed)
    if spec.get("backend") == "javascript-ipc-handler-v1":
        orig = spec.get("original_module")
        cases = spec.get("test_cases", [])
        return verify_js_handlers_live(orig, artifact, cases)
    if Path(artifact).suffix == ".ts":
        return audit_typescript_parity(envelope, Path(artifact))
    if Path(artifact).suffix == ".rs":
        return audit_rust_parity(envelope, Path(artifact))
    return {
        "status": "INCOMPLETE", "coverage_percent": 0.0,
        "reason": "NO_EXECUTABLE_BEHAVIOR_SPECIFICATION",
    }


def audit_typescript_parity(envelope: EvidenceEnvelopeV2, ts_file: Path) -> Dict[str, Any]:
    """Valida paridad exacta de canales IPC en ipc_contracts.ts."""
    if not ts_file.is_file():
        return {
            "status": "FAIL",
            "reason": f"Archivo de contratos no encontrado: {ts_file}",
            "missing_channels": [ch.channel for ch in envelope.ipc_channels],
            "coverage_percent": 0.0,
        }

    content = ts_file.read_text(encoding="utf-8")
    expected_channels = [ch.channel for ch in envelope.ipc_channels]
    missing = []
    found = 0

    for ch in expected_channels:
        # Busca la presencia de la cadena exacta del canal en el archivo
        pattern = re.compile(rf'["\']{re.escape(ch)}["\']')
        if pattern.search(content):
            found += 1
        else:
            missing.append(ch)

    total = len(expected_channels)
    coverage = (found / total * 100.0) if total > 0 else 100.0

    return {
        "status": "INCOMPLETE" if not missing else "FAIL",
        "scope": "channel-name diagnostic only; no behavior has been executed",
        "reason": "NO_LIVE_DIFFERENTIAL_VERIFICATION",
        "total_expected": total,
        "total_verified": found,
        "coverage_percent": round(coverage, 2),
        "missing_channels": missing,
    }


def audit_rust_parity(envelope: EvidenceEnvelopeV2, rs_file: Path) -> Dict[str, Any]:
    """Valida paridad exacta de canales IPC en ipc_contracts.rs."""
    if not rs_file.is_file():
        return {
            "status": "FAIL",
            "reason": f"Archivo de contratos no encontrado: {rs_file}",
            "missing_channels": [ch.channel for ch in envelope.ipc_channels],
            "coverage_percent": 0.0,
        }

    content = rs_file.read_text(encoding="utf-8")
    expected_channels = [ch.channel for ch in envelope.ipc_channels]
    missing = []
    found = 0

    for ch in expected_channels:
        pattern = re.compile(rf'rename\s*=\s*["\']{re.escape(ch)}["\']')
        if pattern.search(content):
            found += 1
        else:
            missing.append(ch)

    total = len(expected_channels)
    coverage = (found / total * 100.0) if total > 0 else 100.0

    return {
        "status": "INCOMPLETE" if not missing else "FAIL",
        "scope": "channel-name diagnostic only; no behavior has been executed",
        "reason": "NO_LIVE_DIFFERENTIAL_VERIFICATION",
        "total_expected": total,
        "total_verified": found,
        "coverage_percent": round(coverage, 2),
        "missing_channels": missing,
    }


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 rea_auditor.py <evidence_json_path> <reconstructed_file_path>")
        sys.exit(1)

    evidence_path = Path(sys.argv[1]).resolve()
    reconstructed_path = Path(sys.argv[2]).resolve()

    print(f"[*] REA Auditor iniciando falsación popperiana...")
    print(f"  - Evidencia: {evidence_path}")
    print(f"  - Contrato:  {reconstructed_path}")

    with open(evidence_path, "r") as f:
        data = json.load(f)
    envelope = EvidenceEnvelopeV2.model_validate(data)

    audit = audit_reconstruction(envelope, reconstructed_path)

    print("\n[+] DICTAMEN DE AUDITORÍA POPPERIANA:")
    print(f"  - Veredicto:         {audit['status']}")
    print(f"  - Cobertura del alcance declarado: {audit['coverage_percent']}%")
    print(f"  - Motivo: {audit.get('reason', 'MISSING_CHANNELS')}")
    report_path = reconstructed_path.with_suffix(reconstructed_path.suffix + ".verification.json")
    report_path.write_text(json.dumps(audit, indent=2))
    print(f"  - Informe: {report_path}")

    sys.exit(0 if audit['status'] == "PASS" else 1)


if __name__ == "__main__":
    main()
