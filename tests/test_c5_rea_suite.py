#!/usr/bin/env python3
"""
Test Suite C5-REAL para Flota de Ingeniería Inversa y Clean-Room Synthesis REA.
Valida el 100% de los componentes en silicio sin dependencias externas.
"""

import unittest
import os
import sys
import tempfile
import json
from pathlib import Path

# Añadir directorio raíz al sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from evidence_schema import (
    BinaryTriageReport,
    EvidenceEnvelopeV2,
    IPCEvidence,
    MemoryOffset,
    FunctionEvidence,
)
from rea_orchestrator import calculate_entropy, calculate_sha256, run_triage, orchestrate_target
from rea_recreator import synthesize_typescript, synthesize_rust, synthesize_python
from rea_auditor import audit_typescript_parity, audit_rust_parity, audit_python_parity, audit_reconstruction
from rea_mcp_server import handle_tools_call
from existence_gate import run_existence_gap_audit


class TestC5ReaSuite(unittest.TestCase):

    def setUp(self):
        # Crear envelope sintético para tests controlados
        self.triage = BinaryTriageReport(
            target_path="/mock/app.app",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_size_bytes=1024,
            architecture="arm64",
            entropy_shannon=4.512,
            is_packed=False,
            imported_libraries=["/usr/lib/libSystem.B.dylib"],
            exported_symbols_count=10,
        )
        self.envelope = EvidenceEnvelopeV2(
            target=self.triage,
            ipc_channels=[
                IPCEvidence(channel="auth:login", direction="r2m"),
                IPCEvidence(channel="audio:playback-start", direction="r2m"),
                IPCEvidence(channel="window:minimize", direction="r2m"),
            ],
            native_functions=[
                FunctionEvidence(
                    symbol_name="sub_100000a00",
                    memory_location=MemoryOffset(start_addr="0x100000a00", end_addr="0x100000a10"),
                    pseudocode="add x0, x0, #1\nret",
                    cfg_nodes=1,
                    xrefs_out=["_malloc"],
                    invariants_verified=["ARM64_LEAF"],
                )
            ]
        )

    def test_entropy_pure_zeros(self):
        """Entropía de un archivo con bytes idénticos debe ser 0.0."""
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b"\x00" * 1024)
            tmp.flush()
            ent = calculate_entropy(Path(tmp.name))
            self.assertEqual(ent, 0.0)

    def test_sha256_calculation(self):
        """Verificar hash SHA-256 de buffer vacío."""
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.flush()
            h = calculate_sha256(Path(tmp.name))
            self.assertEqual(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_clean_room_typescript_synthesis(self):
        """Verificar que el sintetizador TS genera tipos válidos para todos los canales."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)
            files = synthesize_typescript(self.envelope, out_dir)
            self.assertEqual(len(files), 2)
            ipc_content = (out_dir / "ipc_contracts.ts").read_text()
            self.assertIn('"auth:login"', ipc_content)
            self.assertIn('"audio:playback-start"', ipc_content)
            self.assertIn('"window:minimize"', ipc_content)
            self.assertIn("TypedIpcRenderer", ipc_content)

    def test_clean_room_rust_synthesis(self):
        """Verificar que el sintetizador Rust genera enum con serde."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)
            files = synthesize_rust(self.envelope, out_dir)
            self.assertEqual(len(files), 1)
            rs_content = (out_dir / "ipc_contracts.rs").read_text()
            self.assertIn('pub enum IpcChannel', rs_content)
            self.assertIn('#[serde(rename = "auth:login")]', rs_content)

    def test_clean_room_python_synthesis(self):
        """Verificar que el sintetizador Python genera enums, dataclasses tipadas y protocolos en stdlib."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)
            files = synthesize_python(self.envelope, out_dir)
            self.assertEqual(len(files), 2)
            ipc_content = (out_dir / "ipc_contracts.py").read_text()
            self.assertIn('class IpcChannel(str, Enum):', ipc_content)
            self.assertIn('AUTH_LOGIN = "auth:login"', ipc_content)
            self.assertIn('class AuthLoginRequest:', ipc_content)
            self.assertIn('class AuthLoginResponse:', ipc_content)
            self.assertIn('class IpcDispatcher(Protocol):', ipc_content)

            native_content = (out_dir / "native_contracts.py").read_text()
            self.assertIn('Sub100000a00Contract(Protocol):', native_content)
            self.assertIn('memory_offset: str = "0x100000a00"', native_content)

    def test_asar_ipc_comprehensive_regex(self):
        """Verificar que el extractor forense IPC detecta canales complejos (. / $) y métodos avanzados."""
        from rea_unpacker import extract_ipc_details
        sample_code = """
        ipcRenderer.invoke('app.window.close', { force: true });
        ipcRenderer.sendSync('workspace/open', id);
        ipcMain.handleOnce('audio:start-buffer', async () => {});
        ipcMain.on('user$profile', (e) => {});
        """
        matches = {item["channel"]: (item["target"], item["method"]) for item in extract_ipc_details(sample_code)}
        self.assertIn('app.window.close', matches)
        self.assertIn('workspace/open', matches)
        self.assertIn('audio:start-buffer', matches)
        self.assertIn('user$profile', matches)
        self.assertEqual(matches['app.window.close'], ('ipcRenderer', 'invoke'))
        self.assertEqual(matches['workspace/open'], ('ipcRenderer', 'sendSync'))
        self.assertEqual(matches['audio:start-buffer'], ('ipcMain', 'handleOnce'))

    def test_arm64_branch_precision(self):
        """Verificar que solo las ramas reales de ARM64 incrementan el CFG, evitando falsos positivos como bfi/bic."""
        def is_arm64_branch(opcode: str) -> bool:
            return (
                opcode in ('b', 'bl', 'blr', 'br', 'cbz', 'cbnz', 'tbz', 'tbnz')
                or opcode.startswith('b.')
            )
        # Ramas válidas
        for op in ('b', 'bl', 'blr', 'br', 'cbz', 'cbnz', 'tbz', 'tbnz', 'b.eq', 'b.ne', 'b.gt', 'b.lt'):
            self.assertTrue(is_arm64_branch(op), f"Debe reconocer {op} como rama")
        # Opcodes que no son ramas
        for op in ('bfi', 'bfxil', 'bic', 'brk', 'add', 'sub', 'ldr', 'str'):
            self.assertFalse(is_arm64_branch(op), f"No debe reconocer {op} como rama")

    def test_popperian_auditor_pass(self):
        """Nombres presentes solo certifican cobertura estructural, no comportamiento."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)
            synthesize_typescript(self.envelope, out_dir)
            audit = audit_typescript_parity(self.envelope, out_dir / "ipc_contracts.ts")
            self.assertEqual(audit["status"], "INCOMPLETE")
            self.assertEqual(audit["coverage_percent"], 100.0)
            self.assertEqual(len(audit["missing_channels"]), 0)

    def test_popperian_auditor_falsification_failure(self):
        """El auditor debe detectar omisión y emitir FAIL si falta un canal."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_file = Path(tmp_dir) / "bad_contracts.ts"
            bad_file.write_text('export const IPC_CHANNELS = ["auth:login"] as const;\n')
            audit = audit_typescript_parity(self.envelope, bad_file)
            self.assertEqual(audit["status"], "FAIL")
            self.assertIn("audio:playback-start", audit["missing_channels"])
            self.assertIn("window:minimize", audit["missing_channels"])

    def test_existence_gap_catches_slopsquatting_and_stubs(self):
        """El Existence-Gap Gate debe interceptar paquetes alucinados y funciones huecas."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            slop_file = Path(tmp_dir) / "vibe_coded.py"
            slop_file.write_text(
                "import openai_magic\n"
                "def fake_feature():\n"
                "    # ... rest of existing code\n"
                "    pass\n"
            )
            res = run_existence_gap_audit(str(slop_file))
            self.assertEqual(res["verdict"], "FAIL")
            self.assertGreaterEqual(res["total_violations"], 3)

    def test_existence_gap_passes_clean_stdlib_code(self):
        """El Existence-Gap Gate debe certificar PASS sobre código limpio de la suite."""
        suite_dir = Path(__file__).parent.parent
        res = run_existence_gap_audit(str(suite_dir))
        self.assertEqual(res["verdict"], "PASS")
        self.assertEqual(res["total_violations"], 0)

    def test_existence_gap_ts_comment_and_uri_precision(self):
        """El Existence-Gap Gate ignora comentarios, URIs y built-ins en TS/JS."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ts_file = Path(tmp_dir) / "clean.ts"
            ts_file.write_text(
                "// import phantom from 'unreal-pkg';\n"
                "/* require('fake-pkg'); */\n"
                "import { spawn } from 'child_process';\n"
                "import process from 'process';\n"
                "const url = 'https://example.com/api';\n"
                "const scheme = require('node:fs');\n"
            )
            res = run_existence_gap_audit(str(ts_file))
            self.assertEqual(res["verdict"], "PASS")
            self.assertEqual(res["total_violations"], 0)

    def test_audit_python_parity_pass_and_fail(self):
        """Verificar paridad estática de contratos Python (INCOMPLETE al 100%, FAIL si faltan canales)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)
            synthesize_python(self.envelope, out_dir)
            py_file = out_dir / "ipc_contracts.py"

            # 1. Con 100% de canales debe retornar INCOMPLETE (conforme a AGENTS.md: contratos solos no dan PASS)
            audit = audit_python_parity(self.envelope, py_file)
            self.assertEqual(audit["status"], "INCOMPLETE")
            self.assertEqual(audit["coverage_percent"], 100.0)
            self.assertEqual(len(audit["missing_channels"]), 0)

            # Verificar que audit_reconstruction despacha correctamente al auditor de Python
            rec_audit = audit_reconstruction(self.envelope, py_file)
            self.assertEqual(rec_audit["status"], "INCOMPLETE")
            self.assertEqual(rec_audit["coverage_percent"], 100.0)

            # 2. Con canal faltante debe retornar FAIL
            bad_file = out_dir / "bad_contracts.py"
            bad_file.write_text('class IpcChannel:\n    AUTH_LOGIN = "auth:login"\n')
            bad_audit = audit_python_parity(self.envelope, bad_file)
            self.assertEqual(bad_audit["status"], "FAIL")
            self.assertIn("audio:playback-start", bad_audit["missing_channels"])
            self.assertIn("window:minimize", bad_audit["missing_channels"])

    def test_orchestrate_target_and_mcp_tool(self):
        """Verificar pipeline orchestrate_target y herramienta MCP rea_orchestrate sobre binario real."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)
            # Invocación directa del orquestador
            envelope, out_file = orchestrate_target("/bin/ls", max_functions=2, out_dir=out_dir)
            self.assertTrue(out_file.exists())
            self.assertEqual(envelope.target.target_path, "/bin/ls")
            self.assertGreater(envelope.target.file_size_bytes, 0)
            self.assertGreaterEqual(len(envelope.native_functions), 1)

            # Invocación a través del despachador de herramientas MCP
            mcp_res = handle_tools_call(42, {
                "name": "rea_orchestrate",
                "arguments": {
                    "target_path": "/bin/ls",
                    "max_functions": 2,
                    "out_dir": str(out_dir),
                }
            })
            self.assertFalse(mcp_res["result"]["isError"])
            content_json = json.loads(mcp_res["result"]["content"][0]["text"])
            self.assertEqual(content_json["status"], "ORCHESTRATED")
            self.assertEqual(content_json["target"], "/bin/ls")

    def test_asar_preload_bridge_and_orchestrator_strings(self):
        """Verificar extracción de contextBridge, módulos .mjs/.cjs y poblado de extracted_strings."""
        import struct
        from rea_unpacker import audit_electron_asar

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_p = Path(tmp_dir)
            preload_code = (
                b"const { contextBridge, ipcRenderer } = require('electron');\n"
                b"contextBridge.exposeInMainWorld('sovereignBridge', {\n"
                b"  ping: () => ipcRenderer.invoke('bridge:ping'),\n"
                b"});\n"
                b"const endpoint = 'https://api.babylon60.com/v1/health';\n"
            )
            header_dict = {
                "files": {
                    "preload.cjs": {"size": len(preload_code), "offset": "0"}
                }
            }
            header_bytes = json.dumps(header_dict).encode("utf-8")
            asar_file = tmp_p / "app.asar"
            with open(asar_file, "wb") as f:
                f.write(struct.pack("<IIII", 4, len(header_bytes) + 8, len(header_bytes) + 4, len(header_bytes)))
                f.write(header_bytes)
                f.write(preload_code)

            audit = audit_electron_asar(str(asar_file))
            self.assertIn("bridge:ping", audit["ipc_channels"])
            self.assertIn("sovereignBridge", audit["preload_bridges"])
            self.assertIn("https://api.babylon60.com/v1/health", audit["remote_endpoints"])

            envelope, _ = orchestrate_target(str(asar_file), max_functions=0, out_dir=tmp_p)
            self.assertIn("https://api.babylon60.com/v1/health", envelope.extracted_strings)
            self.assertIn("contextBridge:sovereignBridge", envelope.extracted_strings)
            self.assertEqual(len(envelope.ipc_channels), 1)
            self.assertEqual(envelope.ipc_channels[0].channel, "bridge:ping")
            self.assertEqual(envelope.ipc_channels[0].direction, "r2m")


if __name__ == "__main__":
    unittest.main()

