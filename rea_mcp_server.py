#!/usr/bin/env python3
"""
REA Fast MCP Server (High-Performance JSON-RPC stdio Engine) - C5-REAL Ring-0.
Expone las herramientas del microkernel forense REA sobre el protocolo Model Context Protocol (MCP):
- rea_triage
- rea_inspect_asar
- rea_decompile_cfg
- rea_synthesize
- rea_audit_parity
Functional verification runs real subprocesses; its latency depends on the corpus.
"""

import sys
import os
import json
from pathlib import Path
from typing import Dict, Any

from rea_orchestrator import run_triage
from rea_unpacker import audit_electron_asar
from rea_decompiler import extract_function_cfg
from rea_recreator import run_recreation
from rea_auditor import audit_reconstruction
from evidence_schema import EvidenceEnvelopeV2
from existence_gate import run_existence_gap_audit


def send_response(response: Dict[str, Any]):
    """Envía un mensaje JSON-RPC delimitado por nueva línea."""
    serialized = json.dumps(response)
    sys.stdout.write(serialized + "\n")
    sys.stdout.flush()


def handle_initialize(msg_id: Any) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "c5-rea",
                "version": "1.0.0"
            }
        }
    }


def handle_tools_list(msg_id: Any) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "tools": [
                {
                    "name": "rea_triage",
                    "description": "Triage no invasivo de binarios: arquitectura, entropía de Shannon y hashes.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target_path": {"type": "string", "description": "Ruta al binario o bundle .app"}
                        },
                        "required": ["target_path"]
                    }
                },
                {
                    "name": "rea_inspect_asar",
                    "description": "Auditoría forense in-memory de paquetes Electron app.asar y canales IPC (<15ms).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "asar_path": {"type": "string", "description": "Ruta al archivo .asar"}
                        },
                        "required": ["asar_path"]
                    }
                },
                {
                    "name": "rea_decompile_cfg",
                    "description": "Descompilación estática de funciones Mach-O, Control Flow Graphs y stubs de llamadas.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "binary_path": {"type": "string", "description": "Ruta al ejecutable nativo"},
                            "max_functions": {"type": "integer", "description": "Número máximo de funciones (default: 5)"}
                        },
                        "required": ["binary_path"]
                    }
                },
                {
                    "name": "rea_synthesize",
                    "description": "Genera contratos, o una implementación Python autónoma cuando la evidencia contiene un modelo aprendido. Los contratos no prueban comportamiento.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "evidence_path": {"type": "string", "description": "Ruta al archivo JSON de evidencia"},
                            "lang": {"type": "string", "enum": ["ts", "rust", "py", "c"], "description": "Lenguaje objetivo; Python por defecto"},
                            "contracts_only": {"type": "boolean", "default": False, "description": "Generar solo contratos, explícitamente sin reconstrucción ejecutable"}
                        },
                        "required": ["evidence_path"]
                    }
                },
                {
                    "name": "rea_reconstruct",
                    "description": "Learn a standalone byte-stream implementation from a real executable; PASS requires fresh live differential tests, within fixed argv scope.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "original_argv": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                            "output_directory": {"type": "string"},
                        },
                        "required": ["original_argv", "output_directory"],
                    },
                },
                {
                    "name": "rea_reconstruct_binary",
                    "description": "Translate the complete supported ARM64 Mach-O text section to C, compile a standalone native executable and require live exact differential tests with OS denial of access to the original. No target-specific implementation or source input.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "original_path": {"type": "string"},
                            "output_directory": {"type": "string"},
                            "seed": {"type": "integer"},
                            "public_abi": {"type": "string", "description": "Optional path to JSON descriptor of public_abi and link_dependencies"},
                        },
                        "required": ["original_path", "output_directory"],
                    },
                },
                {
                    "name": "rea_recover_javascript",
                    "description": "Recover JavaScript AST and string tables using an explicit caller-provided Babel toolchain. Returns INCOMPLETE because AST recovery alone never certifies application parity.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "original_path": {"type": "string"},
                            "output_directory": {"type": "string"},
                            "toolchain": {"type": "string", "description": "Directory with Babel packages and package-lock.json"},
                            "node": {"type": "string", "default": "node"},
                        },
                        "required": ["original_path", "output_directory", "toolchain"],
                    },
                },
                {
                    "name": "rea_reconstruct_lmstudio",
                    "description": "Generate a native executable from public ABI declarations and real GGUF weights. PASS requires fresh exact comparisons against installed LM Studio while its server is stopped during candidate inference.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "model_file": {"type": "string"},
                            "model_id": {"type": "string"},
                            "library": {"type": "string"},
                            "chat_api": {"type": "boolean", "default": False},
                            "advanced": {"type": "boolean", "default": False},
                            "renderer": {"type": "string"},
                            "headers": {"type": "string"},
                            "reference_url": {"type": "string", "default": "http://127.0.0.1:1234"},
                            "context_length": {"type": "integer", "default": 1024},
                            "output_directory": {"type": "string"},
                            "manage_reference": {"type": "boolean", "default": False},
                        },
                        "required": ["model_file", "model_id", "library", "headers", "output_directory"],
                    },
                },
                {
                    "name": "rea_audit_parity",
                    "description": "Live behavioral comparison against the original. Contracts alone produce INCOMPLETE, never PASS.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "evidence_path": {"type": "string", "description": "Ruta al dossier JSON de evidencia"},
                            "contract_path": {"type": "string", "description": "Ruta a la implementación o contrato generado"},
                            "report_path": {"type": "string", "description": "Ruta opcional del informe JSON de verificación"},
                            "seed": {"type": "integer", "description": "Semilla reproducible opcional"},
                            "manage_reference": {"type": "boolean", "default": False},
                        },
                        "required": ["evidence_path", "contract_path"]
                    }
                },
                {
                    "name": "rea_existence_gap",
                    "description": "Firewall Popperiano contra alucinaciones de LLMs, slopsquatting, imports fantasma y stubs truncados (<15ms).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target_path": {"type": "string", "description": "Ruta al archivo o directorio a auditar"}
                        },
                        "required": ["target_path"]
                    }
                }
            ]
        }
    }


def handle_tools_call(msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    tool_name = params.get("name")
    args = params.get("arguments", {})

    failed = False
    try:
        if tool_name == "rea_triage":
            report = run_triage(args["target_path"])
            text = report.model_dump_json(indent=2)
        elif tool_name == "rea_inspect_asar":
            audit = audit_electron_asar(args["asar_path"])
            text = json.dumps(audit, indent=2)
        elif tool_name == "rea_decompile_cfg":
            max_f = args.get("max_functions", 5)
            funcs = extract_function_cfg(args["binary_path"], max_functions=max_f)
            text = json.dumps([f.model_dump() for f in funcs], indent=2)
        elif tool_name == "rea_synthesize":
            lang = args.get("lang", "py")
            files = run_recreation(args["evidence_path"], target_lang=lang, contracts_only=args.get("contracts_only", False))
            text = json.dumps({"status": "GENERATED_UNVERIFIED", "files": [str(path) for path in files]})
        elif tool_name == "rea_reconstruct":
            from rea_behavior import reconstruct
            res = reconstruct(args["original_argv"], args["output_directory"])
            text = json.dumps(res, indent=2)
            failed = res["status"] != "PASS"
        elif tool_name == "rea_reconstruct_binary":
            from rea_lift import reconstruct_binary
            public_abi_path = args.get("public_abi")
            dependencies = json.loads(Path(public_abi_path).read_text()) if public_abi_path else {}
            res = reconstruct_binary(
                args["original_path"],
                args["output_directory"],
                args.get("seed"),
                dependencies.get("public_abi"),
                dependencies.get("link_dependencies"),
            )
            text = json.dumps(res, indent=2)
            failed = res["status"] != "PASS"
        elif tool_name == "rea_recover_javascript":
            from rea_javascript import recover_javascript
            try:
                res = recover_javascript(
                    args["original_path"],
                    args["output_directory"],
                    args["toolchain"],
                    args.get("node", "node"),
                )
            except (OSError, ValueError) as error:
                res = {"status": "INCOMPLETE", "reason": str(error)}
            text = json.dumps({k: v for k, v in res.items() if k != "files"}, indent=2)
            failed = True
        elif tool_name == "rea_reconstruct_lmstudio":
            from rea_llm import reconstruct_native
            if args.get("chat_api", False):
                from rea_chat import reconstruct_chat
                if not args.get("renderer"):
                    raise ValueError("--chat-api requires --renderer for the real model chat template")
                res = reconstruct_chat(
                    args["model_file"],
                    args["library"],
                    args["renderer"],
                    args["headers"],
                    args.get("reference_url", "http://127.0.0.1:1234"),
                    args["model_id"],
                    args["output_directory"],
                    args.get("manage_reference", False),
                    args.get("context_length", 1024),
                    advanced=args.get("advanced", False),
                )
            else:
                if args.get("advanced", False):
                    raise ValueError("--advanced requires --chat-api")
                res = reconstruct_native(
                    args["model_file"],
                    args["library"],
                    args["headers"],
                    args.get("reference_url", "http://127.0.0.1:1234"),
                    args["model_id"],
                    args["output_directory"],
                    args.get("manage_reference", False),
                    args.get("context_length", 1024),
                )
            text = json.dumps(res, indent=2)
            failed = res["status"] != "PASS"
        elif tool_name == "rea_audit_parity":
            ev_p = Path(args["evidence_path"]).resolve()
            ct_p = Path(args["contract_path"]).resolve()
            with open(ev_p, "r") as f:
                data = json.load(f)
            envelope = EvidenceEnvelopeV2.model_validate(data)
            res = audit_reconstruction(
                envelope,
                ct_p,
                seed=args.get("seed"),
                manage_reference=args.get("manage_reference", False),
            )
            report_path = Path(args["report_path"]) if args.get("report_path") else ct_p.with_suffix(ct_p.suffix + ".verification.json")
            report_path.write_text(json.dumps(res, indent=2))
            text = json.dumps({k: v for k, v in res.items() if k != "cases"}, indent=2)
            failed = res["status"] != "PASS"
        elif tool_name == "rea_existence_gap":
            res = run_existence_gap_audit(args["target_path"])
            text = json.dumps(res, indent=2)
        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Herramienta desconocida: {tool_name}"}
            }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": text}],
                "isError": failed
            }
        }
    except Exception as e:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": f"Error ejecutando {tool_name}: {str(e)}"}],
                "isError": True
            }
        }


def main():
    """Bucle principal JSON-RPC stdio."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            method = req.get("method")
            msg_id = req.get("id")

            if method == "initialize":
                send_response(handle_initialize(msg_id))
            elif method == "notifications/initialized":
                pass
            elif method == "tools/list":
                send_response(handle_tools_list(msg_id))
            elif method == "tools/call":
                send_response(handle_tools_call(msg_id, req.get("params", {})))
            elif method == "ping":
                send_response({"jsonrpc": "2.0", "id": msg_id, "result": {}})
            else:
                if msg_id is not None:
                    send_response({
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32601, "message": f"Método no encontrado: {method}"}
                    })
        except Exception as e:
            sys.stderr.write(f"[rea_mcp_server] Error procesando mensaje: {e}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    main()
