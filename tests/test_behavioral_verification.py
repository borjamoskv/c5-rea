"""Regression tests for the distinction between names and executable behavior."""

import base64
import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from evidence_schema import BinaryTriageReport, EvidenceEnvelopeV2, IPCEvidence
from rea_auditor import audit_typescript_parity, audit_reconstruction
from rea_behavior import (
    _program_ast, audit_behavior, generate_executable, learn_transducer,
    UnsupportedBehavior, _invoke,
)


class BehavioralVerificationTests(unittest.TestCase):
    def test_names_in_comments_cannot_certify_functional_parity(self):
        evidence = EvidenceEnvelopeV2(
            target=BinaryTriageReport("unused", "0" * 64, 0, "unknown", 0),
            ipc_channels=[IPCEvidence("cart:add", "r2m")],
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "comments.ts"
            path.write_text('// "cart:add"\n')
            result = audit_typescript_parity(evidence, path)
        self.assertNotEqual(result["status"], "PASS")

    def test_missing_behavior_cannot_pass_for_python_or_empty_contract(self):
        evidence = EvidenceEnvelopeV2(
            target=BinaryTriageReport("unused", "0" * 64, 0, "unknown", 0),
        )
        self.assertEqual(audit_reconstruction(evidence, Path("unused.py"))["status"], "INCOMPLETE")

    def test_invalid_transition_is_not_compiled(self):
        with self.assertRaises(ValueError):
            _program_ast({"transitions": [[[2, ""]] * 256]})

    def test_process_timeout_is_a_failure_not_a_matching_result(self):
        result = _invoke([sys.executable, "-c", "import time; time.sleep(1)"], b"", timeout=0.02)
        self.assertEqual(result, {"error": "TIMEOUT"})

    def test_cli_and_mcp_contract_audits_are_not_successful(self):
        from rea_mcp_server import handle_tools_call
        evidence = EvidenceEnvelopeV2(
            target=BinaryTriageReport("unused", "0" * 64, 0, "unknown", 0),
            ipc_channels=[IPCEvidence("cart:add", "r2m")],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dossier, contract = root / "evidence.json", root / "comments.ts"
            dossier.write_text(evidence.model_dump_json())
            contract.write_text('// "cart:add"\n')
            process = subprocess.run([
                sys.executable, str(Path(__file__).parent.parent / "c5_rea_cli.py"),
                "audit", str(dossier), str(contract),
            ], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(json.loads(process.stdout)["status"], "INCOMPLETE")
            result = handle_tools_call(1, {"name": "rea_audit_parity", "arguments": {
                "evidence_path": str(dossier), "contract_path": str(contract),
            }})
            self.assertTrue(result["result"]["isError"])

    def test_synthesis_does_not_silently_fall_back_to_interfaces(self):
        from rea_recreator import run_recreation
        evidence = EvidenceEnvelopeV2(
            target=BinaryTriageReport("unused", "0" * 64, 0, "unknown", 0),
            ipc_channels=[IPCEvidence("cart:add", "r2m")],
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(evidence.model_dump_json())
            with self.assertRaisesRegex(ValueError, "No executable model"):
                run_recreation(str(path), out_base_dir=str(Path(directory) / "out"))


@unittest.skipUnless(shutil.which("tr"), "Requires an existing system tr executable")
class RealExecutableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No reference implementation: learn solely from the installed application.
        cls.evidence, cls.observations = learn_transducer([shutil.which("tr"), "-s", "\n"])

    def test_learned_stateful_program_matches_live_original(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = copy.deepcopy(self.evidence)
            artifact = generate_executable(evidence, Path(directory))[0]
            result = audit_behavior(evidence, artifact, seed=820459)
            self.assertEqual(result["status"], "PASS", result.get("reason"))
            self.assertGreaterEqual(result["model_states"], 2)
            self.assertGreater(result["verified_cases"], 300)
            self.assertEqual(result["verified_cases"], result["total_cases"])
            # The generated program also runs with no executable search path.
            payload = bytes(range(256)) * 3
            original = subprocess.run(evidence.clean_room_specification["original_argv"], input=payload, capture_output=True, env={"LC_ALL": "C"})
            candidate = subprocess.run([sys.executable, "-I", "-S", str(artifact)], input=payload, capture_output=True, env={"PATH": ""})
            self.assertEqual((candidate.returncode, candidate.stdout, candidate.stderr),
                             (original.returncode, original.stdout, original.stderr))

    def test_automatically_mutated_transition_fails_live_execution(self):
        # Mutate learned data, not a manually written negative implementation.
        with tempfile.TemporaryDirectory() as directory:
            evidence = copy.deepcopy(self.evidence)
            table = evidence.clean_room_specification["model"]["transitions"]
            table[0][0][1] = base64.b64encode(b"unexpected").decode()
            artifact = generate_executable(evidence, Path(directory))[0]
            result = audit_behavior(evidence, artifact, seed=820460)
            self.assertEqual(result["status"], "FAIL")
            self.assertLess(result["verified_cases"], result["total_cases"])
            self.assertTrue(any(not case["matches"] for case in result["cases"]))

    def test_changed_original_and_candidate_cannot_reuse_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = copy.deepcopy(self.evidence)
            artifact = generate_executable(evidence, Path(directory))[0]
            evidence.clean_room_specification["original_sha256"] = "0" * 64
            self.assertEqual(audit_behavior(evidence, artifact)["reason"], "ORIGINAL_DIGEST_MISMATCH")
            evidence = copy.deepcopy(self.evidence)
            artifact = generate_executable(evidence, Path(directory))[0]
            artifact.write_text(artifact.read_text() + "print('incorrect')\n")
            self.assertEqual(audit_behavior(evidence, artifact)["status"], "FAIL")

    @unittest.skipUnless(shutil.which("rev"), "Requires system rev")
    def test_unsupported_reordering_does_not_get_an_implementation(self):
        with self.assertRaises(UnsupportedBehavior):
            learn_transducer([shutil.which("rev")])


if __name__ == "__main__":
    unittest.main()
