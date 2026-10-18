#!/usr/bin/env python3
"""
REA Fast MCP Server (High-Performance JSON-RPC stdio Engine) - C5-REAL Ring-0.
Expone las herramientas del microkernel forense REA sobre el protocolo Model Context Protocol (MCP):
- rea_triage
- rea_inspect_asar
- rea_decompile_cfg
- rea_synthesize
- rea_audit_parity
Latencia por invocación < 20 ms, sin wrappers de Node ni volcados masivos.
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
from rea_auditor import audit_typescript_parity, audit_rust_parity
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
                    "description": "Síntesis Clean-Room de interfaces y contratos (TypeScript, Rust o Python).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "evidence_path": {"type": "string", "description": "Ruta al archivo JSON de evidencia"},
                            "lang": {"type": "string", "enum": ["ts", "rust", "py"], "description": "Lenguaje objetivo"}
                        },
                        "required": ["evidence_path"]
                    }
                },
                {
                    "name": "rea_audit_parity",
                    "description": "Falsación popperiana de paridad de contratos contra la evidencia extraída.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "evidence_path": {"type": "string", "description": "Ruta al dossier JSON de evidencia"},
                            "contract_path": {"type": "string", "description": "Ruta al archivo generado (.ts o .rs)"}
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
            lang = args.get("lang", "ts")
            files = run_recreation(args["evidence_path"], target_lang=lang)
            text = f"Generados {len(files)} archivos en {files[0].parent if files else 'N/A'}:\n" + "\n".join(str(f) for f in files)
        elif tool_name == "rea_audit_parity":
            ev_p = Path(args["evidence_path"]).resolve()
            ct_p = Path(args["contract_path"]).resolve()
            with open(ev_p, "r") as f:
                data = json.load(f)
            envelope = EvidenceEnvelopeV2.model_validate(data)
            if ct_p.suffix == ".ts":
                res = audit_typescript_parity(envelope, ct_p)
            else:
                res = audit_rust_parity(envelope, ct_p)
            text = json.dumps(res, indent=2)
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
                "isError": False
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
