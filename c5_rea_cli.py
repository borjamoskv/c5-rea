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
from rea_auditor import audit_reconstruction
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
    p_synth = subparsers.add_parser("synthesize", help="Compilar una implementación ejecutable desde evidencia aprendida")
    p_synth.add_argument("evidence", help="Ruta al dossier JSON de evidencia")
    p_synth.add_argument("--lang", choices=["ts", "rust", "py", "c"], default="py", help="Lenguaje objetivo; la recuperación binaria emite C y un ejecutable nativo")
    p_synth.add_argument("--out", default=None, help="Directorio de salida")
    p_synth.add_argument("--contracts-only", action="store_true", help="Solicitar solo interfaces de diagnóstico; no son una reconstrucción ejecutable")

    # Subcomando audit
    p_audit = subparsers.add_parser("audit", help="Verificar comportamiento contra el original; contratos solos no dan PASS")
    p_audit.add_argument("evidence", help="Ruta al dossier JSON de evidencia")
    p_audit.add_argument("contract", help="Ruta a la implementación o al contrato")
    p_audit.add_argument("--report", help="Ruta del informe JSON con todas las comparaciones")
    p_audit.add_argument("--seed", type=int, default=None, help="Semilla reproducible para casos nuevos")
    p_audit.add_argument("--manage-reference", action="store_true", help="Permitir detener y restaurar LM Studio durante la verificación nativa")

    p_reconstruct = subparsers.add_parser(
        "reconstruct", help="Aprender un transductor de bytes de un ejecutable real y verificar su implementación",
    )
    p_reconstruct.add_argument("--out", required=True, help="Directorio de implementación, evidencias y pruebas")
    p_reconstruct.add_argument("original", nargs=argparse.REMAINDER, help="-- ejecutable [argumentos]")

    p_binary = subparsers.add_parser("reconstruct-binary", help="Recuperar instrucciones ARM64 de un Mach-O, traducirlas a C, compilar y verificar contra el original")
    p_binary.add_argument("original", help="Binario original; no se necesita su código fuente")
    p_binary.add_argument("--out", required=True)
    p_binary.add_argument("--seed", type=int, default=None)
    p_binary.add_argument("--public-abi", help="Descriptor JSON de declaraciones públicas y bibliotecas con hashes; sin lógica de aplicación")

    p_js = subparsers.add_parser("recover-javascript", help="Recuperar AST y cadenas de JavaScript; no certifica equivalencia de una aplicación")
    p_js.add_argument("original")
    p_js.add_argument("--out", required=True)
    p_js.add_argument("--toolchain", required=True, help="Directorio externo con Babel y package-lock.json")
    p_js.add_argument("--node", default="node")

    p_native = subparsers.add_parser("reconstruct-lmstudio", help="Generar inferencia nativa con pesos GGUF reales y comparar contra LM Studio")
    p_native.add_argument("--model-file", required=True)
    p_native.add_argument("--model-id", required=True)
    p_native.add_argument("--library", required=True, help="libllama independiente con ABI público verificado")
    p_native.add_argument("--headers", required=True, help="Directorio de declaraciones C del motor")
    p_native.add_argument("--chat-api", action="store_true", help="Generar servidor HTTP de chat y SSE y verificar eventos contra LM Studio")
    p_native.add_argument("--advanced", action="store_true", help="Exigir temperatura, herramientas reales y concurrencia de dos/cuatro peticiones; necesita --chat-api")
    p_native.add_argument("--renderer", help="Biblioteca nativa del evaluador Jinja del modelo (para --chat-api)")
    p_native.add_argument("--reference-url", default="http://127.0.0.1:1234")
    p_native.add_argument("--context-length", type=int, default=1024)
    p_native.add_argument("--out", required=True)
    p_native.add_argument("--manage-reference", action="store_true")

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
        import json
        try:
            files = run_recreation(args.evidence, target_lang=args.lang, out_base_dir=args.out, contracts_only=args.contracts_only)
        except (ValueError, OSError) as error:
            print(json.dumps({"status": "INCOMPLETE", "reason": str(error)}))
            sys.exit(1)
        print(json.dumps({"status": "GENERATED_UNVERIFIED", "contracts_only": args.contracts_only, "files": [str(path) for path in files]}))
    elif args.command == "audit":
        import json
        ev_p = Path(args.evidence).resolve()
        ct_p = Path(args.contract).resolve()
        with open(ev_p, "r") as f:
            data = json.load(f)
        envelope = EvidenceEnvelopeV2.model_validate(data)
        res = audit_reconstruction(envelope, ct_p, seed=args.seed, manage_reference=args.manage_reference)
        report_path = Path(args.report) if args.report else ct_p.with_suffix(ct_p.suffix + ".verification.json")
        report_path.write_text(json.dumps(res, indent=2))
        print(json.dumps({k: v for k, v in res.items() if k != "cases"}, indent=2))
        sys.exit(0 if res["status"] == "PASS" else 1)
    elif args.command == "recover-javascript":
        import json
        from rea_javascript import recover_javascript
        try:
            res = recover_javascript(args.original, args.out, args.toolchain, args.node)
        except (OSError, ValueError) as error:
            res = {"status": "INCOMPLETE", "reason": str(error)}
        print(json.dumps({k: v for k, v in res.items() if k != 'files'}, indent=2))
        sys.exit(1)  # AST recovery cannot certify complete application parity.
    elif args.command == "reconstruct-lmstudio":
        import json
        from rea_llm import reconstruct_native
        try:
            if args.chat_api:
                from rea_chat import reconstruct_chat
                if not args.renderer:
                    raise ValueError("--chat-api requires --renderer for the real model chat template")
                res = reconstruct_chat(args.model_file, args.library, args.renderer, args.headers,
                                       args.reference_url, args.model_id, args.out,
                                       args.manage_reference, args.context_length, advanced=args.advanced)
            else:
                if args.advanced:
                    raise ValueError('--advanced requires --chat-api')
                res = reconstruct_native(args.model_file, args.library, args.headers, args.reference_url,
                                         args.model_id, args.out, args.manage_reference, args.context_length)
        except (OSError, ValueError) as error:
            res = {"status": "INCOMPLETE", "reason": str(error)}
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["status"] == "PASS" else 1)
    elif args.command == "reconstruct-binary":
        import json
        from rea_lift import reconstruct_binary
        dependencies = json.loads(Path(args.public_abi).read_text()) if args.public_abi else {}
        res = reconstruct_binary(args.original, args.out, args.seed,
                                 dependencies.get('public_abi'), dependencies.get('link_dependencies'))
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["status"] == "PASS" else 1)
    elif args.command == "reconstruct":
        import json
        from rea_behavior import reconstruct, UnsupportedBehavior
        command = args.original[1:] if args.original[:1] == ["--"] else args.original
        try:
            res = reconstruct(command, args.out)
        except (UnsupportedBehavior, ValueError, OSError) as error:
            res = {"status": "INCOMPLETE", "reason": str(error)}
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["status"] == "PASS" else 1)
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

