#!/usr/bin/env python3
"""
Stdlib MCP stdio adapter for REA forensic tools.
Uses explicit handshake versions, validated arguments and bounded JSON frames.
Functional verification runs real subprocesses; its latency depends on the corpus.
"""

import sys
import os
import json
import math
import select
import signal
import subprocess
import tempfile
import time
import urllib.parse
from collections import deque
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from typing import Dict, Any, Optional

from rea_orchestrator import run_triage
from rea_unpacker import audit_electron_asar
from rea_decompiler import extract_function_cfg
from rea_recreator import run_recreation
from rea_auditor import audit_reconstruction
from evidence_schema import EvidenceEnvelopeV2
from existence_gate import run_existence_gap_audit


# 2025-03-26 is the only handshake revision that allows JSON-RPC batches.
# 2026-07-28 removed the initialize session entirely and is rejected.
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_FUNCTIONS = 256
MAX_STRING_CHARS = 32768
MAX_PATH_CHARS = 4096
MAX_ARRAY_ITEMS = 256
MAX_INPUT_FILE_BYTES = 8 * 1024 * 1024
MAX_CONTEXT_LENGTH = 1024 * 1024
PATH_FIELDS = {
    "target_path", "asar_path", "binary_path", "evidence_path", "output_directory",
    "out_dir", "contract_path", "report_path", "original_path", "toolchain", "node",
    "model_file", "library", "renderer", "headers", "public_abi",
}
# In-flight cancellation follows the 2025-11-25 rule: stop the work and send no response.
DEFAULT_TOOL_TIMEOUTS = {
    "rea_triage": 60,
    "rea_inspect_asar": 60,
    "rea_decompile_cfg": 120,
    "rea_existence_gap": 120,
    "rea_orchestrate": 180,
    "rea_synthesize": 180,
    "rea_recover_javascript": 180,
    "rea_audit_parity": 300,
    "rea_reconstruct": 300,
    "rea_reconstruct_binary": 300,
    "rea_reconstruct_lmstudio": 600,
}
_STOP = False
_WAKE_FDS = ()
_TIMEOUT_WARNING = False


def protocol_features(version: str) -> Dict[str, bool]:
    """Capabilities that actually changed between the supported revisions."""
    return {
        "annotations": version != "2024-11-05",
        "structuredContent": version in ("2025-06-18", "2025-11-25"),
        "batches": version == "2025-03-26",
    }


def log_error(message: str):
    """Protocol traffic stays on stdout; diagnostics are one stderr line."""
    cleaned = str(message).replace("\r", " ").replace("\n", " ")
    sys.stderr.write(f"[rea_mcp_server] {cleaned}\n")
    sys.stderr.flush()


def rpc_error(msg_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": msg_id, "error": error}


def tool_error(msg_id: Any, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": {
        "content": [{"type": "text", "text": message}], "isError": True}}


def _encode_response(response: Dict[str, Any]) -> str:
    """Finish serialization before writing any bytes to the protocol stream."""
    encoder = json.JSONEncoder(allow_nan=False, ensure_ascii=True, separators=(",", ":"))
    chunks = []
    size = 1  # Include the newline delimiter; ASCII encoding makes len byte-exact.
    for chunk in encoder.iterencode(response):
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise OverflowError("Response exceeds configured byte limit")
        chunks.append(chunk)
    return "".join(chunks) + "\n"


def serialize_message(response: Any) -> str:
    """Finish serialization before any protocol byte is written."""
    try:
        return _encode_response(response)
    except (ValueError, TypeError, RecursionError, OverflowError) as error:
        message = ("Response exceeds the configured byte limit; narrow the input. "
                   "The tool may have completed; inspect output files before retrying."
                   if isinstance(error, OverflowError) else "Backend returned invalid JSON data")
        if isinstance(response, dict):
            result = response.get("result", {})
            if isinstance(result, dict) and "content" in result:
                replacement = tool_error(response.get("id"), message)
            else:
                replacement = rpc_error(response.get("id"), -32603, message)
        else:
            replacement = rpc_error(None, -32603, message)
        log_error(f"Response rejected: {type(error).__name__}")
        return json.dumps(replacement, allow_nan=False, separators=(",", ":")) + "\n"


def send_response(response: Any):
    """Never emit partial JSON or kill the session on a bad backend response."""
    if isinstance(response, DeferredTool):
        response = rpc_error(response.msg_id, -32603, "Internal server error")
    serialized = serialize_message(response)
    sys.stdout.write(serialized)
    sys.stdout.flush()


def handle_initialize(msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(params, dict):
        return rpc_error(msg_id, -32602, "initialize params must be an object")
    requested = params.get("protocolVersion")
    client = params.get("clientInfo")
    if (not isinstance(requested, str) or not requested
            or not isinstance(params.get("capabilities"), dict)
            or not isinstance(client, dict)
            or not all(isinstance(client.get(key), str) and client[key]
                       for key in ("name", "version"))):
        return rpc_error(msg_id, -32602,
                         "initialize requires protocolVersion, capabilities and clientInfo.name/version")
    version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[-1]
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "protocolVersion": version,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "c5-rea",
                "version": "1.0.0"
            }
        }
    }


def handle_tools_list(msg_id: Any, protocol_version: str = SUPPORTED_PROTOCOL_VERSIONS[-1]) -> Dict[str, Any]:
    response = {
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
                    "name": "rea_orchestrate",
                    "description": "Ejecuta el pipeline forense completo sobre un binario o paquete .app/.asar y retorna el EvidenceEnvelopeV2 consolidado.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target_path": {"type": "string", "description": "Ruta al binario o bundle .app"},
                            "max_functions": {"type": "integer", "default": 8, "description": "Máximo de funciones nativas con CFG (default: 8)"},
                            "out_dir": {"type": "string", "description": "Directorio opcional donde guardar el dossier JSON"}
                        },
                        "required": ["target_path"]
                    }
                },
                {
                    "name": "rea_inspect_asar",
                    "description": "Auditoría forense in-memory de paquetes Electron app.asar y canales IPC; la duración depende del paquete.",
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
                            "contracts_only": {"type": "boolean", "default": False, "description": "Generar solo contratos, explícitamente sin reconstrucción ejecutable"},
                            "output_directory": {"type": "string", "description": "Directorio opcional de salida; evita depender de la ubicación del dossier"}
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
                    "description": "Auditoría estática de imports fantasma y stubs truncados; FAIL se comunica como error de herramienta y un objetivo vacío no certifica PASS.",
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
    read_only = {"rea_triage", "rea_inspect_asar", "rea_decompile_cfg", "rea_existence_gap"}
    open_world = {"rea_reconstruct", "rea_reconstruct_binary", "rea_reconstruct_lmstudio", "rea_audit_parity"}
    features = protocol_features(protocol_version)
    for tool in response["result"]["tools"]:
        schema = tool["inputSchema"]
        schema["additionalProperties"] = False
        for name, field in schema["properties"].items():
            if field["type"] == "string":
                field["minLength"] = 1
                if name == "reference_url":
                    field["maxLength"] = 2048
                    field["format"] = "uri"
                elif name in PATH_FIELDS:
                    field["maxLength"] = MAX_PATH_CHARS
                else:
                    field["maxLength"] = MAX_STRING_CHARS
            elif field["type"] == "array":
                field["maxItems"] = MAX_ARRAY_ITEMS
                items = field.get("items")
                if isinstance(items, dict) and items.get("type") == "string":
                    items["maxLength"] = MAX_STRING_CHARS
            elif name == "max_functions":
                field.update(minimum=0 if tool["name"] == "rea_orchestrate" else 1,
                             maximum=MAX_FUNCTIONS)
            elif name == "context_length":
                field["minimum"] = 1
                field["maximum"] = MAX_CONTEXT_LENGTH
            elif name == "seed":
                field["minimum"] = -2 ** 63
                field["maximum"] = 2 ** 63 - 1
        if features["annotations"]:
            readonly = tool["name"] in read_only
            tool["annotations"] = {
                "readOnlyHint": readonly,
                "destructiveHint": not readonly,
                "idempotentHint": readonly,
                "openWorldHint": tool["name"] in open_world,
            }
    return response


def _argument_leaf(name: str):
    leaf = name.rsplit(".", 1)[-1]
    if "[" in leaf and leaf.endswith("]"):
        field, _, index = leaf[:-1].partition("[")
        return field, int(index)
    return leaf, None


def tool_timeout_seconds(tool_name: str) -> float:
    """REA_MCP_TOOL_TIMEOUT_SECONDS overrides every tool; otherwise use the table."""
    global _TIMEOUT_WARNING
    raw = os.environ.get("REA_MCP_TOOL_TIMEOUT_SECONDS")
    if raw:
        try:
            value = float(raw)
        except ValueError:
            value = -1
        if math.isfinite(value) and value > 0:
            return value
        if not _TIMEOUT_WARNING:
            _TIMEOUT_WARNING = True
            log_error("Ignoring invalid REA_MCP_TOOL_TIMEOUT_SECONDS; using per-tool defaults")
    return float(DEFAULT_TOOL_TIMEOUTS.get(tool_name, 300))


def validate_argument(value: Any, schema: Dict[str, Any], name: str) -> Any:
    """Validate the small JSON Schema subset used by this server's own tools."""
    expected = schema["type"]
    if expected == "integer":
        if type(value) is float and math.isfinite(value) and value.is_integer():
            value = int(value)
        valid = type(value) is int
    else:
        valid = isinstance(value, {"object": dict, "array": list,
                                   "string": str, "boolean": bool}[expected])
    if not valid:
        raise ValueError(f"{name} must be {expected}")
    if expected == "object":
        properties = schema["properties"]
        missing = set(schema.get("required", ())) - value.keys()
        unknown = value.keys() - properties.keys()
        if missing:
            raise ValueError(f"{name} missing required fields: {', '.join(sorted(missing))}")
        if unknown and schema.get("additionalProperties") is False:
            raise ValueError(f"{name} unknown fields: {', '.join(sorted(unknown))}")
        return {key: validate_argument(item, properties[key], f"{name}.{key}")
                for key, item in value.items()}
    if expected == "array":
        if len(value) < schema.get("minItems", 0):
            raise ValueError(f"{name} must contain at least {schema['minItems']} items")
        if len(value) > schema.get("maxItems", MAX_ARRAY_ITEMS):
            raise ValueError(f"{name} must contain at most {schema.get('maxItems', MAX_ARRAY_ITEMS)} items")
        return [validate_argument(item, schema["items"], f"{name}[{index}]")
                for index, item in enumerate(value)]
    if expected == "string":
        limit = schema.get("maxLength", MAX_STRING_CHARS)
        if len(value) < schema.get("minLength", 0) or len(value) > limit:
            raise ValueError(f"{name} length must be between {schema.get('minLength', 0)} and {limit}")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError(f"{name} must not contain control characters")
        leaf, index = _argument_leaf(name)
        path_like = leaf in PATH_FIELDS or (
            leaf == "original_argv" and (index == 0 or "/" in value or "\\" in value))
        if path_like and any(part == ".." for part in value.replace("\\", "/").split("/")):
            raise ValueError(f"{name} must not contain '..' path segments")
        if leaf == "reference_url":
            parsed = urllib.parse.urlsplit(value)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ValueError(f"{name} must be an http(s) URL")
    if expected == "integer":
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{name} must be >= {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError(f"{name} must be <= {schema['maximum']}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{name} must be one of {schema['enum']}")
    return value


@contextmanager
def tool_diagnostics():
    """Protect stdout from Python prints, native writes and inherited child output."""
    descriptor = None
    saved = None
    try:
        sys.stdout.flush()
        descriptor = sys.stdout.fileno()
        error_descriptor = sys.stderr.fileno()
    except (AttributeError, OSError, ValueError):
        # In-process callers may capture streams with StringIO instead of OS pipes.
        descriptor = None
    if descriptor is not None:
        saved = os.dup(descriptor)
    try:
        if saved is not None:
            os.dup2(error_descriptor, descriptor)
        with redirect_stdout(sys.stderr):
            yield
    finally:
        if saved is not None:
            try:
                os.dup2(saved, descriptor)
            finally:
                os.close(saved)


def prepare_tool_call(msg_id: Any, params: Dict[str, Any]):
    """Validate a tools/call envelope. Returns ('error', response) or ('ok', call)."""
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        return "error", rpc_error(msg_id, -32602, "tools/call requires an object with a tool name")
    if not isinstance(params.get("arguments", {}), dict):
        return "error", rpc_error(msg_id, -32602, "arguments must be an object")
    if "task" in params:
        return "error", rpc_error(msg_id, -32602, "Task-augmented execution is not supported")
    meta = params.get("_meta")
    if isinstance(meta, dict) and meta.get("io.modelcontextprotocol/protocolVersion") == "2026-07-28":
        return "error", rpc_error(
            msg_id, -32602, "Protocol 2026-07-28 is not implemented",
            {"supported": list(SUPPORTED_PROTOCOL_VERSIONS), "requested": "2026-07-28"})
    tool = next((tool for tool in handle_tools_list(None)["result"]["tools"]
                 if tool["name"] == params["name"]), None)
    if tool is None:
        return "error", rpc_error(msg_id, -32602, f"Unknown tool: {params['name']}")
    try:
        args = validate_argument(params.get("arguments", {}), tool["inputSchema"], "arguments")
        if "original_argv" in args and not args["original_argv"][0]:
            raise ValueError("original_argv[0] must name an executable")
    except ValueError as error:
        return "error", tool_error(msg_id, str(error))
    return "ok", {"name": params["name"], "arguments": args}


def _attach_structured(response: Dict[str, Any], protocol_version: str) -> Dict[str, Any]:
    if "result" in response:
        try:
            data = strict_json_loads(response["result"]["content"][0]["text"])
            if not isinstance(data, (dict, list)):
                raise ValueError("Expected a JSON object or array")
        except (ValueError, KeyError, IndexError, TypeError, RecursionError):
            if response["result"].get("isError") is True:
                return response
            return tool_error(response.get("id"), "Backend returned invalid JSON data")
        if protocol_features(protocol_version)["structuredContent"]:
            response["result"]["structuredContent"] = data if isinstance(data, dict) else {"items": data}
    return response


def handle_tools_call(msg_id: Any, params: Dict[str, Any],
                      protocol_version: str = SUPPORTED_PROTOCOL_VERSIONS[-1]) -> Dict[str, Any]:
    kind, payload = prepare_tool_call(msg_id, params)
    if kind == "error":
        return payload
    # Descriptor redirection is process-wide; this server intentionally runs sequentially.
    with tool_diagnostics():
        response = _execute_tool(msg_id, payload)
    return _attach_structured(response, protocol_version)


def _within_directory(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _read_json_file(path: Path, limit: Optional[int] = None) -> Any:
    if limit is None:
        limit = MAX_INPUT_FILE_BYTES
    if not path.is_file():
        raise ValueError(f"{path.name} must be an existing file")
    if path.stat().st_size > limit:
        raise ValueError(f"{path.name} exceeds the {limit} byte input limit")
    return strict_json_loads(path.read_text(encoding="utf-8"))


def _report_destination(report_path: Path, protected_inputs) -> Path:
    """Check output aliases and directory shape before expensive verification."""
    for source in protected_inputs:
        if (report_path.resolve() == source.resolve()
                or (report_path.exists() and source.exists() and report_path.samefile(source))):
            raise ValueError("report_path must not overwrite evidence_path or contract_path")
    if report_path.is_symlink():
        raise ValueError("report_path must not be a symlink")
    if not report_path.parent.is_dir():
        raise ValueError("report_path parent directory must exist")
    if report_path.exists() and not report_path.is_file():
        raise ValueError("report_path must name a regular file")
    return report_path.parent.resolve() / report_path.name


def _atomic_report(report_path: Path, report: Dict[str, Any]):
    """Replace the report only after complete, strict JSON has been written."""
    serialized = json.dumps(report, indent=2, allow_nan=False)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=report_path.parent,
                                         prefix=f".{report_path.name}.", suffix=".tmp",
                                         delete=False) as output:
            temporary_path = Path(output.name)
            output.write(serialized)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, report_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _execute_tool(msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    tool_name = params.get("name")
    args = params.get("arguments", {})

    failed = False
    try:
        if tool_name == "rea_triage":
            report = run_triage(args["target_path"])
            text = report.model_dump_json(indent=2)
        elif tool_name == "rea_orchestrate":
            from rea_orchestrator import orchestrate_target
            max_f = args.get("max_functions", 8)
            out_d = Path(args["out_dir"]).resolve() if args.get("out_dir") else None
            envelope, out_file = orchestrate_target(args["target_path"], max_functions=max_f, out_dir=out_d)
            if out_d is not None and not _within_directory(out_d, Path(out_file)):
                raise ValueError("dossier escaped out_dir")
            if not Path(out_file).is_file():
                text = json.dumps({"status": "INCOMPLETE", "reason": "NO_DOSSIER",
                                   "dossier_path": str(out_file)})
                failed = True
            else:
                text = json.dumps({
                    "status": "ORCHESTRATED",
                    "target": envelope.target.target_path,
                    "dossier_path": str(out_file),
                    "ipc_channels_count": len(envelope.ipc_channels),
                    "native_functions_count": len(envelope.native_functions),
                    "electron_fuses": envelope.target.electron_fuses,
                    "envelope": envelope.model_dump(),
                }, indent=2)
        elif tool_name == "rea_inspect_asar":
            audit = audit_electron_asar(args["asar_path"])
            text = json.dumps(audit, indent=2)
        elif tool_name == "rea_decompile_cfg":
            if not Path(args["binary_path"]).is_file():
                raise ValueError("binary_path must be an existing file")
            max_f = args.get("max_functions", 5)
            funcs = extract_function_cfg(args["binary_path"], max_functions=max_f)
            if funcs:
                text = json.dumps([f.model_dump() for f in funcs], indent=2)
            else:
                text = json.dumps({"status": "INCOMPLETE", "reason": "NO_FUNCTIONS_EXTRACTED",
                                   "binary_path": args["binary_path"], "functions": []})
                failed = True
        elif tool_name == "rea_synthesize":
            lang = args.get("lang", "py")
            evidence = Path(args["evidence_path"])
            _read_json_file(evidence)
            files = run_recreation(args["evidence_path"], target_lang=lang,
                                   out_base_dir=args.get("output_directory"),
                                   contracts_only=args.get("contracts_only", False))
            output_root = (Path(args["output_directory"]) if args.get("output_directory")
                           else evidence.resolve().parent.parent / "reconstructed" / lang)
            if files:
                for path in files:
                    if not Path(path).is_file():
                        raise ValueError(f"Generated artifact is missing: {path}")
                    if not _within_directory(output_root, Path(path)):
                        raise ValueError(f"Generated artifact escaped the output directory: {path}")
                text = json.dumps({"status": "GENERATED_UNVERIFIED", "files": [str(path) for path in files]})
            else:
                text = json.dumps({"status": "INCOMPLETE", "reason": "NO_ARTIFACTS_GENERATED", "files": []})
                failed = True
        elif tool_name == "rea_reconstruct":
            from rea_behavior import reconstruct
            res = reconstruct(args["original_argv"], args["output_directory"])
            text = json.dumps(res, indent=2)
            failed = res["status"] != "PASS"
        elif tool_name == "rea_reconstruct_binary":
            from rea_lift import reconstruct_binary
            public_abi_path = args.get("public_abi")
            dependencies = _read_json_file(Path(public_abi_path)) if public_abi_path else {}
            if not isinstance(dependencies, dict):
                raise ValueError("public_abi must contain a JSON object")
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
            report_path = (Path(args["report_path"]) if args.get("report_path")
                           else ct_p.with_suffix(ct_p.suffix + ".verification.json"))
            report_path = _report_destination(report_path, (ev_p, ct_p))
            data = _read_json_file(ev_p)
            envelope = EvidenceEnvelopeV2.model_validate(data)
            res = audit_reconstruction(
                envelope,
                ct_p,
                seed=args.get("seed"),
                manage_reference=args.get("manage_reference", False),
            )
            if not isinstance(res, dict) or res.get("status") not in {"PASS", "FAIL", "INCOMPLETE"}:
                raise ValueError("Verification backend returned an invalid verdict")
            _atomic_report(report_path, res)
            text = json.dumps({**{k: v for k, v in res.items() if k != "cases"},
                               "report_path": str(report_path.resolve())}, indent=2)
            failed = res["status"] != "PASS"
        elif tool_name == "rea_existence_gap":
            target = Path(args["target_path"])
            if not (target.is_file() or target.is_dir()):
                raise ValueError("target_path must be an existing file or directory")
            res = run_existence_gap_audit(args["target_path"])
            if not res["files_scanned"]:
                res = {**res, "verdict": "INCOMPLETE", "reason": "NO_AUDITABLE_FILES"}
            failed = res["verdict"] != "PASS"
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


class DeferredTool:
    """A validated tools/call that the stdio loop runs in its own process group."""

    def __init__(self, msg_id: Any, params: Dict[str, Any], protocol_version: str):
        self.msg_id = msg_id
        self.params = params
        self.protocol_version = protocol_version
        self.timeout = tool_timeout_seconds(params["name"])


class MCPServer:
    """Sequential stdio session for the advertised handshake protocol versions."""

    def __init__(self):
        self.protocol_version: Optional[str] = None
        self.ready = False
        self.defer_tools = False
        self.inflight_id = None
        self.pending_cancels: Dict[Any, str] = {}
        self.completed_ids = deque()
        self._completed_set = set()

    def remember(self, msg_id: Any):
        if msg_id in self._completed_set:
            return
        self.completed_ids.append(msg_id)
        self._completed_set.add(msg_id)
        while len(self.completed_ids) > 256:
            old = self.completed_ids.popleft()
            if old not in self.completed_ids:
                self._completed_set.discard(old)

    def note_cancel(self, request_id: Any, reason: str):
        """Return inflight, done, or pending. Completed ids are not stored again."""
        if type(request_id) not in (str, int):
            return "invalid"
        if request_id == self.inflight_id:
            return "inflight"
        if request_id in self._completed_set:
            return "done"
        self.pending_cancels[request_id] = reason
        while len(self.pending_cancels) > 64:
            self.pending_cancels.pop(next(iter(self.pending_cancels)))
        return "pending"

    def take_precancel(self, msg_id: Any, method: str) -> bool:
        """Drop a request that was cancelled before it arrived. initialize cannot be cancelled."""
        if msg_id not in self.pending_cancels:
            return False
        reason = self.pending_cancels.pop(msg_id)
        if method == "initialize":
            log_error(f"Ignored cancellation of initialize request {msg_id}")
            return False
        self.remember(msg_id)
        suffix = f": {reason}" if reason else ""
        log_error(f"Dropped cancelled request {msg_id}{suffix}")
        return True

    def dispatch(self, request: Any) -> Any:
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return rpc_error(None, -32600, "Expected a JSON-RPC 2.0 object")
        # No server-to-client requests are sent; do not answer incoming responses.
        if "method" not in request and ("result" in request or "error" in request):
            return None
        method = request.get("method")
        if not isinstance(method, str) or not method:
            return rpc_error(None, -32600, "method must be a nonempty string")
        params = request.get("params", {})
        if "id" not in request:
            if method == "notifications/cancelled":
                _record_cancel(self, params)
            elif (method == "notifications/initialized" and isinstance(params, dict)
                    and self.protocol_version is not None):
                self.ready = True
            # A tools/call notification must never execute a tool with side effects.
            return None
        msg_id = request["id"]
        if type(msg_id) not in (str, int):
            return rpc_error(None, -32600, "id must be a string or integer")
        if isinstance(params, dict) is False:
            return self._done(msg_id, rpc_error(msg_id, -32602, "params must be an object"))
        if method == "notifications/cancelled":
            _record_cancel(self, params)
            return self._done(msg_id, rpc_error(
                msg_id, -32600, "notifications/cancelled must be sent as a notification"))
        if method == "notifications/initialized":
            if self.protocol_version is not None:
                self.ready = True
            if not self.ready:
                return self._done(msg_id, rpc_error(
                    msg_id, -32600, "Send initialize before notifications/initialized"))
            return self._done(msg_id, {"jsonrpc": "2.0", "id": msg_id, "result": {}})
        rejected = _stateless_rejection(msg_id, params)
        if rejected is not None:
            return self._done(msg_id, rejected)
        if self.take_precancel(msg_id, method):
            return None
        if method == "ping":
            return self._done(msg_id, {"jsonrpc": "2.0", "id": msg_id, "result": {}})
        if method == "initialize":
            if self.protocol_version is not None:
                return self._done(msg_id, rpc_error(msg_id, -32600, "Session already initialized"))
            response = handle_initialize(msg_id, params)
            if "result" in response:
                self.protocol_version = response["result"]["protocolVersion"]
            return self._done(msg_id, response)
        if method == "server/discover":
            return self._done(msg_id, rpc_error(
                msg_id, -32601,
                "MCP 2026-07-28 server/discover is not implemented. Supported handshake versions: "
                + ", ".join(SUPPORTED_PROTOCOL_VERSIONS)))
        if method not in ("tools/list", "tools/call"):
            return self._done(msg_id, rpc_error(msg_id, -32601, f"Method not found: {method}"))
        if not self.ready:
            return self._done(msg_id, rpc_error(
                msg_id, -32600, "Send initialize and notifications/initialized first"))
        if method == "tools/list":
            if "cursor" in params:
                return self._done(msg_id, rpc_error(
                    msg_id, -32602, "Unknown cursor; this catalog has one page"))
            return self._done(msg_id, handle_tools_list(msg_id, self.protocol_version))
        kind, payload = prepare_tool_call(msg_id, params)
        if kind == "error":
            return self._done(msg_id, payload)
        if self.defer_tools:
            return DeferredTool(msg_id, payload, self.protocol_version or SUPPORTED_PROTOCOL_VERSIONS[-1])
        return self._done(msg_id, handle_tools_call(msg_id, payload, self.protocol_version))

    def _done(self, msg_id: Any, response: Any):
        self.remember(msg_id)
        return response


def _reject_constant(value: str):
    raise ValueError(f"Invalid JSON constant: {value}")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite JSON number")
    return number


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def strict_json_loads(value: str) -> Any:
    return json.loads(value, parse_constant=_reject_constant, parse_float=_finite_float,
                      object_pairs_hook=_unique_object)


def _stateless_rejection(msg_id: Any, params: Dict[str, Any]):
    meta = params.get("_meta")
    if isinstance(meta, dict) and meta.get("io.modelcontextprotocol/protocolVersion") == "2026-07-28":
        return rpc_error(
            msg_id, -32602, "Protocol 2026-07-28 is not implemented",
            {"supported": list(SUPPORTED_PROTOCOL_VERSIONS), "requested": "2026-07-28"})
    return None


def _parse_cancel(message: Any):
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return None
    if "id" in message or message.get("method") != "notifications/cancelled":
        return None
    params = message.get("params", {})
    if not isinstance(params, dict):
        return None
    request_id = params.get("requestId")
    if type(request_id) not in (str, int):
        return None
    reason = params.get("reason")
    if reason is not None and not isinstance(reason, str):
        reason = ""
    return request_id, reason or ""


def _record_cancel(server: MCPServer, params: Any):
    if not isinstance(params, dict):
        return
    request_id = params.get("requestId")
    reason = params.get("reason") if isinstance(params.get("reason"), str) else ""
    server.note_cancel(request_id, reason)


def _peek_batch_version(server: MCPServer, items) -> Optional[str]:
    if server.protocol_version is not None:
        return server.protocol_version
    for item in items:
        if not isinstance(item, dict) or item.get("method") != "initialize" or "id" not in item:
            continue
        params = item.get("params")
        if isinstance(params, dict) and isinstance(params.get("protocolVersion"), str):
            requested = params["protocolVersion"]
            if requested in SUPPORTED_PROTOCOL_VERSIONS:
                return requested
            return SUPPORTED_PROTOCOL_VERSIONS[-1]
    return None


def _on_stop(signum, frame):
    global _STOP
    _STOP = True


def _on_child(signum, frame):
    """Wake the stdio loop when an isolated tool process exits."""
    return


def _install_stop_signals():
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)
    os.set_blocking(write_fd, False)
    os.set_inheritable(read_fd, False)
    os.set_inheritable(write_fd, False)
    signal.set_wakeup_fd(write_fd)
    signal.signal(signal.SIGTERM, _on_stop)
    signal.signal(signal.SIGINT, _on_stop)
    signal.signal(signal.SIGCHLD, _on_child)
    return read_fd, write_fd


def _drain_fd(fd: int):
    try:
        while os.read(fd, 256):
            pass
    except (BlockingIOError, OSError):
        return


def _kill_group(signum, frame):
    try:
        os.killpg(os.getpid(), signal.SIGKILL)
    except OSError:
        os._exit(128 + int(signum or 15))


def _grouped_popen(original):
    def popen(*args, **kwargs):
        kwargs["start_new_session"] = False
        return original(*args, **kwargs)
    return popen


def _run_tool_child(path: str, msg_id: Any, params: Dict[str, Any], protocol_version: str):
    signal.signal(signal.SIGTERM, _kill_group)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    try:
        signal.set_wakeup_fd(-1)
    except (OSError, ValueError):
        pass
    for fd in _WAKE_FDS:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.setsid()
    except OSError:
        pass
    try:
        null_fd = os.open(os.devnull, os.O_RDONLY)
        try:
            os.dup2(null_fd, 0)
        finally:
            os.close(null_fd)
    except OSError:
        pass
    subprocess.Popen = _grouped_popen(subprocess.Popen)
    try:
        response = handle_tools_call(msg_id, params, protocol_version)
        payload = serialize_message(response).encode("ascii")
    except Exception:
        log_error(f"Tool process failed for request {msg_id}")
        payload = serialize_message(rpc_error(msg_id, -32603, "Internal server error")).encode("ascii")
    try:
        with open(path, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass
    os._exit(0)


class ToolJob:
    def __init__(self, pid: int, msg_id: Any, result_path: str, timeout: float, protocol_version: str):
        self.pid = pid
        self.msg_id = msg_id
        self.result_path = result_path
        self.timeout = timeout
        self.deadline = time.monotonic() + timeout
        self.protocol_version = protocol_version
        self.reason = None
        self._status = None

    def request_stop(self, reason: str):
        if self.reason is None:
            self.reason = reason
        try:
            os.kill(self.pid, signal.SIGTERM)
        except OSError:
            pass

    def poll(self):
        if self._status is not None:
            return self._status
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self._status = 0
            return self._status
        if pid == 0:
            return None
        self._status = status
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except OSError:
            pass
        return status

    def wait_briefly(self, seconds: float):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.poll() is not None:
                return self._status
            time.sleep(0.02)
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            self._status = os.waitpid(self.pid, 0)[1]
        except ChildProcessError:
            self._status = 0
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except OSError:
            pass
        return self._status

    def read_result(self):
        try:
            size = os.path.getsize(self.result_path)
            if size <= 0 or size > MAX_RESPONSE_BYTES:
                return None
            return strict_json_loads(Path(self.result_path).read_text(encoding="ascii"))
        except (OSError, UnicodeError, ValueError, RecursionError):
            return None
        finally:
            self.cleanup()

    def cleanup(self):
        try:
            os.unlink(self.result_path)
        except OSError:
            pass


def start_tool_job(deferred: DeferredTool) -> ToolJob:
    descriptor, path = tempfile.mkstemp(prefix="rea-mcp-result-", suffix=".json")
    os.close(descriptor)
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        pid = os.fork()
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    if pid == 0:
        try:
            _run_tool_child(path, deferred.msg_id, deferred.params, deferred.protocol_version)
        finally:
            os._exit(0)
    return ToolJob(pid, deferred.msg_id, path, deferred.timeout, deferred.protocol_version)


def _timeout_response(job: ToolJob) -> Dict[str, Any]:
    payload = {"status": "INCOMPLETE", "reason": "TIMEOUT", "timeout_seconds": job.timeout}
    result = {"jsonrpc": "2.0", "id": job.msg_id, "result": {
        "content": [{"type": "text", "text": json.dumps(payload)}], "isError": True}}
    if protocol_features(job.protocol_version)["structuredContent"]:
        result["result"]["structuredContent"] = payload
    return result


def _queue_line(queue, line: bytes):
    try:
        parsed = strict_json_loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        queue.append(("frame-error", rpc_error(None, -32700, "Parse error: expected strict UTF-8 JSON")))
        return
    queue.append(("frame", parsed))


def _pull_frames(buffer: bytearray, queue, eof: bool, state: Dict[str, bool]):
    while True:
        if state["draining"]:
            newline = buffer.find(b"\n")
            if newline >= 0:
                del buffer[:newline + 1]
                state["draining"] = False
                queue.append(("frame-error", rpc_error(None, -32600, "Message exceeds 1 MiB")))
                continue
            if eof:
                buffer.clear()
                state["draining"] = False
                queue.append(("frame-error", rpc_error(None, -32600, "Message exceeds 1 MiB")))
            return
        newline = buffer.find(b"\n")
        if newline < 0:
            if len(buffer) > MAX_MESSAGE_BYTES:
                if eof:
                    buffer.clear()
                    queue.append(("frame-error", rpc_error(None, -32600, "Message exceeds 1 MiB")))
                else:
                    state["draining"] = True
                continue
            if eof and buffer.strip():
                line = bytes(buffer)
                del buffer[:]
                _queue_line(queue, line)
            return
        if newline >= MAX_MESSAGE_BYTES:
            del buffer[:newline + 1]
            queue.append(("frame-error", rpc_error(None, -32600, "Message exceeds 1 MiB")))
            continue
        line = bytes(buffer[:newline + 1])
        del buffer[:newline + 1]
        if not line.strip():
            continue
        _queue_line(queue, line)


def _serve_blocking(input_stream, server: MCPServer):
    """Sequential fallback for streams without a file descriptor."""
    server.defer_tools = False
    while True:
        line = input_stream.readline(MAX_MESSAGE_BYTES + 1)
        if not line:
            return
        if isinstance(line, str):
            line = line.encode("utf-8")
        if len(line) > MAX_MESSAGE_BYTES:
            while line and not line.endswith(b"\n"):
                extra = input_stream.readline(MAX_MESSAGE_BYTES + 1)
                line = extra.encode("utf-8") if isinstance(extra, str) else extra
            send_response(rpc_error(None, -32600, "Message exceeds 1 MiB"))
            continue
        if not line.strip():
            continue
        try:
            request = strict_json_loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            send_response(rpc_error(None, -32700, "Parse error: expected strict UTF-8 JSON"))
            continue
        if isinstance(request, list):
            _serve_batch(server, request)
            continue
        try:
            response = server.dispatch(request)
        except Exception as error:
            log_error(f"Dispatch failed: {type(error).__name__}")
            msg_id = request.get("id") if isinstance(request, dict) else None
            response = rpc_error(msg_id if type(msg_id) in (str, int) else None, -32603, "Internal server error")
        if response is not None:
            send_response(response)


def _serve_batch(server: MCPServer, items):
    version = _peek_batch_version(server, items)
    if not items or version is None or not protocol_features(version)["batches"]:
        if not items:
            send_response(rpc_error(None, -32600, "Invalid Request"))
        elif version is None:
            send_response(rpc_error(
                None, -32600,
                "JSON-RPC batches are not supported until protocol 2025-03-26 is negotiated"))
        else:
            send_response(rpc_error(
                None, -32600, f"JSON-RPC batches are not supported for protocol version {version}"))
        return
    responses = []
    for item in items:
        if isinstance(item, list):
            responses.append(rpc_error(None, -32600, "Invalid Request"))
            continue
        try:
            response = server.dispatch(item)
        except Exception as error:
            log_error(f"Dispatch failed: {type(error).__name__}")
            msg_id = item.get("id") if isinstance(item, dict) else None
            response = rpc_error(msg_id if type(msg_id) in (str, int) else None, -32603, "Internal server error")
        if isinstance(response, DeferredTool):
            deferred = response
            response = handle_tools_call(deferred.msg_id, deferred.params, deferred.protocol_version)
            server.remember(deferred.msg_id)
        if response is not None:
            responses.append(response)
    if responses:
        send_response(responses)


def _stop_job(job: Optional[ToolJob], reason: str):
    if job is None:
        return
    job.request_stop(reason)
    job.wait_briefly(1)
    job.cleanup()


def serve(input_stream):
    """Read bounded UTF-8 frames, isolate tool calls, and recover at the next newline."""
    global _STOP, _WAKE_FDS
    _STOP = False
    server = MCPServer()
    try:
        infd = input_stream.fileno()
    except (AttributeError, OSError, ValueError):
        _serve_blocking(input_stream, server)
        return
    if not hasattr(os, "fork"):
        _serve_blocking(input_stream, server)
        return
    server.defer_tools = True
    os.set_blocking(infd, False)
    wake_r, wake_w = _install_stop_signals()
    _WAKE_FDS = (wake_r, wake_w)
    buffer = bytearray()
    eof = False
    state = {"draining": False}
    queue = deque()
    job = None
    batch = None

    def finish_message(response):
        nonlocal batch
        if batch is None:
            if response is not None:
                send_response(response)
            return
        if response is not None:
            batch["responses"].append(response)
        batch["left"] -= 1
        if batch["left"] == 0:
            if batch["responses"]:
                send_response(batch["responses"])
            batch = None

    def finish_job(current: ToolJob):
        status = current.poll()
        clean = status is not None and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        server.inflight_id = None
        if current.reason == "cancel":
            current.cleanup()
            server.remember(current.msg_id)
            log_error(f"Cancelled in-flight request {current.msg_id} without a response")
            finish_message(None)
            return
        if current.reason == "timeout" and not clean:
            current.cleanup()
            server.remember(current.msg_id)
            log_error(f"Tool timed out after {current.timeout}s for request {current.msg_id}")
            finish_message(_timeout_response(current))
            return
        if current.reason == "shutdown":
            current.cleanup()
            return
        parsed = current.read_result()
        server.remember(current.msg_id)
        if parsed is None:
            finish_message(rpc_error(current.msg_id, -32603, "Internal server error"))
        else:
            finish_message(parsed)

    def pull_cancels():
        """Interrupt the running tool without reordering earlier queued requests."""
        if job is None:
            return
        kept = deque()
        while queue:
            kind, message = queue.popleft()
            parsed = _parse_cancel(message) if kind in ("frame", "batch") else None
            if parsed is None or parsed[0] != job.msg_id:
                kept.append((kind, message))
                continue
            _request_id, reason = parsed
            server.note_cancel(job.msg_id, reason)
            job.request_stop("cancel")
            suffix = f": {reason}" if reason else ""
            log_error(f"Cancellation requested for {job.msg_id}{suffix}")
            if kind == "batch":
                finish_message(None)
        queue.extend(kept)

    def dispatch_one(message):
        nonlocal job
        try:
            response = server.dispatch(message)
        except Exception as error:
            log_error(f"Dispatch failed: {type(error).__name__}")
            msg_id = message.get("id") if isinstance(message, dict) else None
            response = rpc_error(msg_id if type(msg_id) in (str, int) else None, -32603, "Internal server error")
        if isinstance(response, DeferredTool):
            try:
                job = start_tool_job(response)
                server.inflight_id = response.msg_id
            except OSError:
                log_error("Unable to isolate tool process")
                server.remember(response.msg_id)
                finish_message(rpc_error(response.msg_id, -32603, "Internal server error"))
            return
        finish_message(response)

    try:
        while not _STOP:
            if job is not None and job.poll() is not None:
                finish_job(job)
                job = None
                continue
            if job is not None and time.monotonic() >= job.deadline:
                job.request_stop("timeout")
                job.wait_briefly(1)
                finish_job(job)
                job = None
                continue
            _pull_frames(buffer, queue, eof, state)
            pull_cancels()
            if _STOP:
                break
            if job is None and queue:
                kind, message = queue.popleft()
                if kind == "frame-error":
                    finish_message(message)
                    continue
                if isinstance(message, list):
                    if kind == "batch" or batch is not None:
                        finish_message(rpc_error(None, -32600, "Invalid Request"))
                        continue
                    version = _peek_batch_version(server, message)
                    allowed = bool(message) and version is not None and protocol_features(version)["batches"]
                    if not allowed:
                        if not message:
                            finish_message(rpc_error(None, -32600, "Invalid Request"))
                        elif version is None:
                            finish_message(rpc_error(
                                None, -32600,
                                "JSON-RPC batches are not supported until protocol 2025-03-26 is negotiated"))
                        else:
                            finish_message(rpc_error(
                                None, -32600,
                                f"JSON-RPC batches are not supported for protocol version {version}"))
                        continue
                    batch = {"responses": [], "left": len(message)}
                    queue.extendleft(("batch", item) for item in reversed(message))
                    continue
                dispatch_one(message)
                continue
            if eof and not queue and job is None and not state["draining"]:
                return
            timeout = 0.2 if job is not None else 0.5
            if job is not None:
                timeout = min(timeout, max(0.0, job.deadline - time.monotonic()))
            watch = [wake_r] if eof else [infd, wake_r]
            readable, _, _ = select.select(watch, [], [], timeout)
            if wake_r in readable:
                _drain_fd(wake_r)
            if infd in readable and not eof:
                try:
                    chunk = os.read(infd, 65536)
                except BlockingIOError:
                    chunk = None
                if chunk == b"":
                    eof = True
                elif chunk:
                    buffer.extend(chunk)
        if job is not None:
            _stop_job(job, "shutdown")
            server.inflight_id = None
    except (BrokenPipeError, KeyboardInterrupt):
        _stop_job(job, "shutdown")
        return
    finally:
        try:
            signal.set_wakeup_fd(-1)
        except (OSError, ValueError):
            pass
        for fd in (wake_r, wake_w):
            try:
                os.close(fd)
            except OSError:
                pass
        _WAKE_FDS = ()


def main():
    """Run until stdin closes, the client disconnects or the process is signalled."""
    try:
        serve(sys.stdin.buffer)
    except (BrokenPipeError, KeyboardInterrupt):
        return


if __name__ == "__main__":
    main()
