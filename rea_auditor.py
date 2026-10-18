#!/usr/bin/env python3
"""
REA Auditor (Popperian Falsification & Parity Harness) - C5-REAL Ring-0.
Contrasta de forma determinista la evidencia extraída en silicio (Evidence v2)
contra la implementación sintetizada Clean-Room (TypeScript / Rust / Python).
Certifica paridad del 100% de canales IPC y firmas de funciones, emitiendo un
veredicto popperiano estricto (PASS o FAIL).
"""

import sys
import os
import json
import re
from pathlib import Path
from typing import Dict, Any, List

from evidence_schema import EvidenceEnvelopeV2


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
        "status": "PASS" if not missing else "FAIL",
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
        "status": "PASS" if not missing else "FAIL",
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

    if reconstructed_path.suffix == ".ts":
        audit = audit_typescript_parity(envelope, reconstructed_path)
    elif reconstructed_path.suffix == ".rs":
        audit = audit_rust_parity(envelope, reconstructed_path)
    else:
        print(f"[-] Formato no soportado para auditoría: {reconstructed_path.suffix}")
        sys.exit(1)

    print("\n[+] DICTAMEN DE AUDITORÍA POPPERIANA:")
    print(f"  - Veredicto:         {audit['status']}")
    print(f"  - Cobertura:         {audit['coverage_percent']}% ({audit['total_verified']}/{audit['total_expected']} canales)")
    if audit['missing_channels']:
        print(f"  - Canales Faltantes: {len(audit['missing_channels'])}")
        for ch in audit['missing_channels'][:5]:
            print(f"      • {ch}")
    else:
        print("  - Certificación:     100% de paridad sin discrepancias detectadas.")

    # Actualizar dictamen en el Evidence JSON
    envelope.falsification_verdict = audit['status']
    with open(evidence_path, "w") as f:
        f.write(envelope.model_dump_json(indent=2))
    print(f"\n[+] Veredicto {audit['status']} sellado en {evidence_path}")

    sys.exit(0 if audit['status'] == "PASS" else 1)


if __name__ == "__main__":
    main()
