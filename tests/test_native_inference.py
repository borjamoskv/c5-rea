"""Failure gates and input coverage; real inference is a separate live audit."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from evidence_schema import BinaryTriageReport, EvidenceEnvelopeV2
from rea_auditor import audit_reconstruction
from rea_llm import BACKEND, _ctype, audit_native, file_hash, inference_cases


class NativeInferenceGuards(unittest.TestCase):
    def envelope(self):
        return EvidenceEnvelopeV2(
            target=BinaryTriageReport("unused.gguf", "0" * 64, 0, "GGUF", None),
            clean_room_specification={"backend": BACKEND, "reference_url": "http://127.0.0.1:1234"},
        )

    def test_unmeasured_entropy_survives_round_trip(self):
        restored = EvidenceEnvelopeV2.model_validate(json.loads(self.envelope().model_dump_json()))
        self.assertIsNone(restored.target.entropy_shannon)

    def test_native_audit_does_not_implicitly_stop_reference(self):
        result = audit_reconstruction(self.envelope(), Path("unused.py"))
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["reason"], "EXPLICIT_REFERENCE_LIFECYCLE_MANAGEMENT_REQUIRED")

    def test_missing_native_executable_is_fail_and_report_is_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit_native(self.envelope(), root / "missing.py", True, root)
            saved = json.loads((root / "verification.json").read_text())
        self.assertEqual(result, saved)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["reason"], "NOT_THE_GENERATED_NATIVE_IMPLEMENTATION")
        self.assertEqual(result["lifecycle"], [])

    def test_unsupported_abi_type_fails_instead_of_guessing(self):
        with self.assertRaisesRegex(ValueError, "Unsupported ABI type"):
            _ctype("unrecognized_native_value")
        self.assertEqual(_ctype("struct llama_batch"), "llama_batch")
        self.assertEqual(_ctype("const char *"), "ct.c_void_p")

    def test_cases_are_fresh_inputs_with_no_expected_answers(self):
        first, second = inference_cases(1), inference_cases(2)
        self.assertNotEqual(first, second)
        self.assertEqual(first[0], first[-1])
        self.assertTrue(any(any(ord(char) > 127 for char in item["prompt"]) for item in first))
        for item in first:
            self.assertEqual(set(item), {"prompt", "temperature", "max_tokens"})
            self.assertEqual(item["temperature"], 0)

    def test_streaming_hash_matches_standard_digest(self):
        payload = bytes(range(256)) * 9000
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data"
            path.write_bytes(payload)
            self.assertEqual(file_hash(path), hashlib.sha256(payload).hexdigest())

    def test_mcp_requires_explicit_native_lifecycle_management(self):
        from rea_mcp_server import handle_tools_call, handle_tools_list
        names = {tool["name"] for tool in handle_tools_list(1)["result"]["tools"]}
        self.assertIn("rea_reconstruct_lmstudio", names)
        self.assertIn("rea_recover_javascript", names)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(self.envelope().model_dump_json())
            response = handle_tools_call(1, {"name": "rea_audit_parity", "arguments": {
                "evidence_path": str(path), "contract_path": str(Path(directory) / "candidate.py"),
            }})
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(json.loads(response["result"]["content"][0]["text"])["status"], "INCOMPLETE")

    def test_mcp_lmstudio_enforces_chat_api_and_renderer_guards(self):
        from rea_mcp_server import handle_tools_call
        base_args = {
            "model_file": "unused.gguf",
            "model_id": "local-model",
            "library": "unused.dylib",
            "headers": "unused_headers",
            "output_directory": "/tmp/unused_out",
        }
        resp_adv = handle_tools_call(1, {
            "name": "rea_reconstruct_lmstudio",
            "arguments": {**base_args, "advanced": True, "chat_api": False},
        })
        self.assertTrue(resp_adv["result"]["isError"])
        self.assertIn("--advanced requires --chat-api", resp_adv["result"]["content"][0]["text"])

        resp_chat = handle_tools_call(2, {
            "name": "rea_reconstruct_lmstudio",
            "arguments": {**base_args, "chat_api": True},
        })
        self.assertTrue(resp_chat["result"]["isError"])
        self.assertIn("--chat-api requires --renderer", resp_chat["result"]["content"][0]["text"])

