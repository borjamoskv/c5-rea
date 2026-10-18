#!/usr/bin/env python3
"""
C5-REA CLI - Suite Unificada de Ingeniería Inversa y Síntesis Clean-Room.
Punto de entrada de línea de comandos para toda la flota de subagentes REA.
"""

import sys
import os
import argparse
from pathlib import Path

from rea_orchestrator import run_triage, inspect_mach_o
from rea_unpacker import audit_electron_asar
from rea_decompiler import extract_function_cfg
from rea_recreator import run_recreation
from rea_auditor import audit_typescript_parity, audit_rust_parity
from rea_mcp_server import main as run_mcp_server
from evidence_schema import EvidenceEnvelopeV2
from existence_gate import run_existence_gap_audit


def main():
    parser = argparse.ArgumentParser(
        prog="c5-rea",
        description="C5-REAL Sovereign Reverse Engineering & Existence-Gap Verification Suite"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando triage
    p_triage = subparsers.add_parser("triage", help="Triage no invasivo de binarios o bundles")
    p_triage.add_argument("target", help="Ruta al binario o bundle .app")

    # Subcomando unpack
    p_unpack = subparsers.add_parser("unpack", help="Auditoría forense in-memory de ASAR Electron")
    p_unpack.add_argument("asar", help="Ruta al archivo app.asar")

    # Subcomando decompile
    p_decompile = subparsers.add_parser("decompile", help="Descompilación estática CFG sobre Mach-O")
    p_decompile.add_argument("binary", help="Ruta al binario nativo")
    p_decompile.add_argument("--max", type=int, default=5, help="Número máximo de funciones")

    # Subcomando synthesize
    p_synth = subparsers.add_parser("synthesize", help="Síntesis Clean-Room a TypeScript, Rust o Python")
    p_synth.add_argument("evidence", help="Ruta al dossier JSON de evidencia")
    p_synth.add_argument("--lang", choices=["ts", "rust", "py"], default="ts", help="Lenguaje objetivo")
    p_synth.add_argument("--out", default=None, help="Directorio de salida")

    # Subcomando audit
    p_audit = subparsers.add_parser("audit", help="Falsación popperiana de paridad")
    p_audit.add_argument("evidence", help="Ruta al dossier JSON de evidencia")
    p_audit.add_argument("contract", help="Ruta al contrato generado (.ts o .rs)")

    # Subcomando existence-gap
    p_egap = subparsers.add_parser(
        "existence-gap",
        help="Firewall Popperiano contra alucinaciones de LLMs, slopsquatting e imports fantasma"
    )
    p_egap.add_argument("target", help="Ruta al archivo o directorio a auditar")

    # Subcomando serve (MCP)
    p_serve = subparsers.add_parser("serve", help="Lanzar servidor MCP sobre stdio")

    args = parser.parse_args()

    if args.command == "triage":
        report = run_triage(args.target)
        print(f"[+] Triage completado: {report.architecture}, {report.entropy_shannon} bits/byte, {report.file_size_bytes} bytes")
    elif args.command == "unpack":
        audit = audit_electron_asar(args.asar)
        print(f"[+] ASAR indexado: {audit['total_files']} archivos, {len(audit['ipc_channels'])} canales IPC")
    elif args.command == "decompile":
        funcs = extract_function_cfg(args.binary, max_functions=args.max)
        print(f"[+] Descompilación completada: {len(funcs)} funciones con CFG extraídas")
    elif args.command == "synthesize":
        files = run_recreation(args.evidence, target_lang=args.lang, out_base_dir=args.out)
        print(f"[+] Síntesis completada: {len(files)} archivos generados en {files[0].parent if files else 'N/A'}")
    elif args.command == "audit":
        import json
        ev_p = Path(args.evidence).resolve()
        ct_p = Path(args.contract).resolve()
        with open(ev_p, "r") as f:
            data = json.load(f)
        envelope = EvidenceEnvelopeV2.model_validate(data)
        if ct_p.suffix == ".ts":
            res = audit_typescript_parity(envelope, ct_p)
        else:
            res = audit_rust_parity(envelope, ct_p)
        print(f"[+] Dictamen Popperiano: {res['status']} ({res['coverage_percent']}% cobertura)")
    elif args.command == "existence-gap":
        import json
        res = run_existence_gap_audit(args.target)
        print(f"[+] Existence-Gap Verdict: {res['verdict']} ({res['files_scanned']} archivos, {res['total_violations']} violaciones)")
        if res["violations"] if "violations" in res else res["reports"]:
            print(json.dumps(res["reports"], indent=2))
            sys.exit(1)
    elif args.command == "serve":
        run_mcp_server()


if __name__ == "__main__":
    main()

