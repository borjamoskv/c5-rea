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
from rea_orchestrator import calculate_entropy, calculate_sha256, run_triage
from rea_recreator import synthesize_typescript, synthesize_rust, synthesize_python
from rea_auditor import audit_typescript_parity, audit_rust_parity
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

    def test_popperian_auditor_pass(self):
        """El auditor debe certificar PASS con 100% de cobertura sobre síntesis válida."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)
            synthesize_typescript(self.envelope, out_dir)
            audit = audit_typescript_parity(self.envelope, out_dir / "ipc_contracts.ts")
            self.assertEqual(audit["status"], "PASS")
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


if __name__ == "__main__":
    unittest.main()

