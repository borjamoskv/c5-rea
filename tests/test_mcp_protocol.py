"""Transport and validation regressions; these do not certify forensic parity."""

import copy
import io
import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import rea_mcp_server as mcp
from evidence_schema import BinaryTriageReport, EvidenceEnvelopeV2, IPCEvidence


ROOT = Path(__file__).resolve().parent.parent


def request(method, msg_id=1, params=None):
    value = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        value["params"] = params
    return value


def handshake(version="2025-11-25"):
    return [request("initialize", 1, {
        "protocolVersion": version, "capabilities": {},
        "clientInfo": {"name": "rea-regression", "version": "1"},
    }), {"jsonrpc": "2.0", "method": "notifications/initialized"}]


class StdioProtocolTests(unittest.TestCase):
    def exchange(self, frames, command=None):
        wire = b"".join((item if isinstance(item, bytes)
                         else json.dumps(item).encode("utf-8")) + b"\n" for item in frames)
        completed = subprocess.run(command or [sys.executable, str(ROOT / "rea_mcp_server.py")],
                                   input=wire, capture_output=True, cwd=ROOT, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        return [json.loads(line) for line in completed.stdout.splitlines()], completed.stderr

    def test_all_advertised_versions_negotiate_and_list_tools(self):
        for version in mcp.SUPPORTED_PROTOCOL_VERSIONS:
            with self.subTest(version=version):
                responses, _ = self.exchange(handshake(version) + [request("tools/list", 2)])
                self.assertEqual(len(responses), 2)
                self.assertEqual(responses[0]["result"]["protocolVersion"], version)
                tools = responses[1]["result"]["tools"]
                self.assertEqual(len(tools), 11)
                self.assertEqual(len({tool["name"] for tool in tools}), len(tools))
                self.assertEqual("annotations" in tools[0], version != "2024-11-05")

    def test_unknown_version_gets_supported_counter_offer(self):
        responses, _ = self.exchange(handshake("2099-01-01"))
        self.assertEqual(responses[0]["result"]["protocolVersion"], "2025-11-25")

    def test_handshake_is_required_before_tools(self):
        init, ready = handshake()
        responses, _ = self.exchange([
            request("tools/list", 0), init, request("tools/list", 2), ready,
            request("tools/list", 3), request("initialize", 4, init["params"]),
        ])
        self.assertEqual([response["id"] for response in responses], [0, 1, 2, 3, 4])
        self.assertEqual(responses[0]["error"]["code"], -32600)
        self.assertEqual(responses[2]["error"]["code"], -32600)
        self.assertIn("tools", responses[3]["result"])
        self.assertEqual(responses[4]["error"]["code"], -32600)

    def test_invalid_initialization_does_not_poison_retry(self):
        responses, _ = self.exchange([request("initialize", 0, {})] + handshake())
        self.assertEqual(responses[0]["error"]["code"], -32602)
        self.assertEqual(responses[1]["result"]["protocolVersion"], "2025-11-25")

    def test_bad_json_utf8_and_duplicate_keys_recover_at_next_line(self):
        bad_frames = [b"{bad", b"\xff", b'{"id":NaN}', b'{"id":Infinity}',
                      b'{"id":1e999}', b'{"id":1,"id":2}']
        responses, _ = self.exchange(bad_frames + [request("ping", 0)])
        self.assertEqual(len(responses), len(bad_frames) + 1)
        for response in responses[:-1]:
            self.assertEqual(response["error"]["code"], -32700)
            self.assertIsNone(response["id"])
        self.assertEqual(responses[-1], {"jsonrpc": "2.0", "id": 0, "result": {}})

    def test_deeply_nested_json_does_not_kill_session(self):
        responses, _ = self.exchange([b"[" * 1500 + b"]" * 1500, request("ping", 8)])
        # Decoder recursion limits differ across supported Python versions.
        self.assertIn(responses[0]["error"]["code"], (-32700, -32600))
        self.assertEqual(responses[1]["id"], 8)

    def test_non_requests_and_invalid_ids_do_not_crash(self):
        bad_frames = [b"null", b"[]", b"42", b'"hello"',
                      {"jsonrpc": "1.0", "id": 4, "method": "ping"},
                      request("ping", True), request("ping", None), request("ping", 1.5),
                      {"jsonrpc": "2.0", "id": 1, "method": []}]
        responses, _ = self.exchange(bad_frames + [request("ping", "alive")])
        self.assertEqual([response["error"]["code"] for response in responses[:-1]],
                         [-32600] * len(bad_frames))
        self.assertEqual(responses[-1]["id"], "alive")

    def test_invalid_params_and_unknown_methods_have_rpc_errors(self):
        responses, _ = self.exchange(handshake() + [
            request("tools/call", 2, []), request("tools/call", 3, {}),
            request("tools/call", 4, {"name": "absent"}),
            request("tools/call", 5, {"name": "rea_triage", "arguments": []}),
            request("absent", 6), request("tools/list", 7, {"cursor": "absent"}),
            request("tools/call", 8, {"name": "rea_triage", "task": {}}),
        ])
        self.assertEqual([response["error"]["code"] for response in responses[1:]],
                         [-32602, -32602, -32602, -32602, -32601, -32602, -32602])

    def test_notifications_and_peer_responses_are_silent(self):
        messages = handshake() + [
            {"jsonrpc": "2.0", "method": "ping"},
            {"jsonrpc": "2.0", "method": "unknown", "params": []},
            {"jsonrpc": "2.0", "id": 90, "result": {}},
            {"jsonrpc": "2.0", "id": 91, "error": {"code": -32601, "message": "ignored"}},
            request("ping", 2),
        ]
        responses, _ = self.exchange(messages)
        self.assertEqual([response["id"] for response in responses], [1, 2])

    def test_oversized_frame_is_drained_and_next_request_survives(self):
        responses, _ = self.exchange([b"x" * (2 * mcp.MAX_MESSAGE_BYTES), request("ping", 9)])
        self.assertEqual(len(responses), 2)
        self.assertEqual(responses[0]["error"]["code"], -32600)
        self.assertEqual(responses[1]["id"], 9)

    def test_cli_serve_entrypoint_and_real_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "clean.py"
            target.write_text("import json\nvalue = json.dumps({'ok': True})\n")
            messages = handshake() + [request("tools/call", 2, {
                "name": "rea_existence_gap", "arguments": {"target_path": str(target)}})]
            responses, stderr = self.exchange(messages, [sys.executable, str(ROOT / "c5_rea_cli.py"), "serve"])
        result = responses[-1]["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["verdict"], "PASS")
        self.assertEqual(json.loads(result["content"][0]["text"]), result["structuredContent"])
        self.assertEqual(stderr, b"")

    def test_python_native_and_child_diagnostics_stay_off_stdout(self):
        code = '''import os, subprocess, sys
import rea_mcp_server as mcp
def noisy(*args, **kwargs):
    print("python diagnostic")
    os.write(1, b"native diagnostic\\n")
    subprocess.run([sys.executable, "-c", "print('child diagnostic')"], check=True)
    raise RuntimeError("deliberate tool failure")
mcp.run_triage = noisy
mcp.main()
'''
        responses, stderr = self.exchange(handshake() + [request("tools/call", 2, {
            "name": "rea_triage", "arguments": {"target_path": "unused"}}), request("ping", 3)],
            [sys.executable, "-c", code])
        self.assertEqual([response["id"] for response in responses], [1, 2, 3])
        self.assertTrue(responses[1]["result"]["isError"])
        for message in (b"python diagnostic", b"native diagnostic", b"child diagnostic"):
            self.assertIn(message, stderr)

    def test_response_is_flushed_before_input_closes(self):
        with subprocess.Popen([sys.executable, str(ROOT / "rea_mcp_server.py")],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, cwd=ROOT) as process:
            try:
                process.stdin.write(json.dumps(request("ping", 7)).encode() + b"\n")
                process.stdin.flush()
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=5), "Server buffered its response until EOF")
                self.assertEqual(json.loads(process.stdout.readline())["id"], 7)
            finally:
                process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0)

    def test_bad_internal_response_does_not_kill_connection(self):
        code = '''import rea_mcp_server as mcp
original = mcp.MCPServer.dispatch
def dispatch(self, request):
    if request.get("id") == 2:
        return {"jsonrpc": "2.0", "id": 2, "result": {"content": [], "bad": float("nan")}}
    return original(self, request)
mcp.MCPServer.dispatch = dispatch
mcp.main()
'''
        responses, _ = self.exchange(handshake() + [request("ping", 2), request("ping", 3)],
                                     [sys.executable, "-c", code])
        self.assertEqual([item["id"] for item in responses], [1, 2, 3])
        self.assertTrue(responses[1]["result"]["isError"])
        self.assertEqual(responses[-1]["result"], {})

    def test_oversized_response_is_replaced_with_an_explicit_error(self):
        code = '''import rea_mcp_server as mcp
mcp.MAX_RESPONSE_BYTES = 4096
original = mcp.MCPServer.dispatch
def dispatch(self, request):
    if request.get("id") == 2:
        return {"jsonrpc": "2.0", "id": 2, "result": {
            "content": [{"type": "text", "text": "evidence" * 4096}], "isError": False}}
    return original(self, request)
mcp.MCPServer.dispatch = dispatch
mcp.main()
'''
        responses, _ = self.exchange(handshake() + [request("ping", 2), request("ping", 3)],
                                     [sys.executable, "-c", code])
        self.assertTrue(responses[1]["result"]["isError"])
        self.assertIn("limit", responses[1]["result"]["content"][0]["text"])
        self.assertEqual(responses[-1]["id"], 3)


class ToolValidationTests(unittest.TestCase):
    def call(self, name, arguments, version="2025-11-25"):
        return mcp.handle_tools_call(42, {"name": name, "arguments": arguments}, version)

    def test_bad_arguments_are_rejected_before_tool_execution(self):
        bad_arguments = [{}, {"target_path": 1}, {"target_path": ""},
                         {"target_path": "bad\x00path"},
                         {"target_path": "unused", "typo": True}]
        with patch.object(mcp, "run_triage") as triage:
            for arguments in bad_arguments:
                with self.subTest(arguments=arguments):
                    self.assertTrue(self.call("rea_triage", arguments)["result"]["isError"])
            triage.assert_not_called()

    def test_boolean_integer_enum_and_array_validation(self):
        cases = [("rea_decompile_cfg", {"binary_path": "unused", "max_functions": value})
                 for value in (True, "5", -1, 0, 257, 1.5)]
        cases += [("rea_synthesize", {"evidence_path": "unused", "lang": "go"}),
                  ("rea_synthesize", {"evidence_path": "unused", "contracts_only": "false"})]
        cases += [("rea_reconstruct", {"output_directory": "unused", "original_argv": value})
                  for value in ([], "echo", [1], [""])]
        with patch.object(mcp, "_execute_tool") as execution:
            for name, arguments in cases:
                with self.subTest(name=name, arguments=arguments):
                    self.assertTrue(self.call(name, arguments)["result"]["isError"])
            execution.assert_not_called()

    def test_integral_json_number_is_normalized_and_empty_argv_argument_is_valid(self):
        with patch.object(mcp, "_execute_tool", return_value=mcp.tool_error(42, "unit result")) as execution:
            self.call("rea_decompile_cfg", {"binary_path": "unused", "max_functions": 2.0})
            self.assertIs(type(execution.call_args.args[1]["arguments"]["max_functions"]), int)
            self.call("rea_reconstruct", {"output_directory": "unused", "original_argv": ["echo", ""]})
            self.assertEqual(execution.call_count, 2)

    def test_tool_notification_cannot_invoke_side_effects(self):
        server = mcp.MCPServer()
        for message in handshake():
            server.dispatch(message)
        with patch.object(mcp, "handle_tools_call") as execute:
            server.dispatch({"jsonrpc": "2.0", "method": "tools/call", "params": {
                "name": "rea_synthesize", "arguments": {"evidence_path": "unused"}}})
            execute.assert_not_called()

    def test_failed_and_empty_audits_are_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for target in (root / "missing", root):
                self.assertTrue(self.call("rea_existence_gap", {"target_path": str(target)})["result"]["isError"])
            target = root / "broken.py"
            target.write_text("def broken(:\n")
            result = self.call("rea_existence_gap", {"target_path": str(target)})["result"]
            self.assertTrue(result["isError"])
            self.assertEqual(result["structuredContent"]["verdict"], "FAIL")

    def test_structured_content_follows_the_negotiated_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            for version, structured in (
                    ("2024-11-05", False), ("2025-03-26", False),
                    ("2025-06-18", True), ("2025-11-25", True)):
                with self.subTest(version=version):
                    result = self.call("rea_existence_gap", {"target_path": directory}, version)["result"]
                    self.assertTrue(result["isError"])
                    self.assertEqual("structuredContent" in result, structured)

    def test_report_cannot_overwrite_inputs_or_their_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, contract = root / "evidence.json", root / "contract.py"
            evidence.write_text('{"keep":true}')
            contract.write_text("keep = True\n")
            symbolic, hard = root / "symbolic.json", root / "hard.json"
            symbolic.symlink_to(evidence)
            os.link(contract, hard)
            with patch.object(mcp, "audit_reconstruction") as audit:
                for destination in (evidence, contract, symbolic, hard):
                    result = self.call("rea_audit_parity", {
                        "evidence_path": str(evidence), "contract_path": str(contract),
                        "report_path": str(destination)})["result"]
                    self.assertTrue(result["isError"])
                    self.assertIn("must not overwrite", result["content"][0]["text"])
                audit.assert_not_called()
            self.assertEqual(evidence.read_text(), '{"keep":true}')
            self.assertEqual(contract.read_text(), "keep = True\n")

    def test_synthesis_honors_explicit_output_directory(self):
        evidence = EvidenceEnvelopeV2(
            target=BinaryTriageReport("unused", "0" * 64, 0, "unknown", 0),
            ipc_channels=[IPCEvidence("sample:read", "r2m")])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dossier = root / "evidence.json"
            dossier.write_text(evidence.model_dump_json())
            arguments = {"evidence_path": str(dossier), "lang": "py", "contracts_only": True,
                         "output_directory": str(root / "chosen")}
            before = copy.deepcopy(arguments)
            result = self.call("rea_synthesize", arguments)["result"]
            self.assertFalse(result["isError"], result)
            files = result["structuredContent"]["files"]
            self.assertTrue(files)
            for filename in files:
                path = Path(filename)
                self.assertTrue(path.is_file())
                self.assertEqual(path.parent, root / "chosen")
            self.assertEqual(arguments, before)

    def test_in_process_python_logging_preserves_capture_streams(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            with patch.object(mcp, "run_triage", side_effect=lambda _: print("diagnostic")):
                result = self.call("rea_triage", {"target_path": "unused"})
        self.assertEqual(output.getvalue(), "")
        self.assertIn("diagnostic", errors.getvalue())
        self.assertTrue(result["result"]["isError"])

    def test_invalid_backend_json_is_error_in_legacy_and_current_modes(self):
        for version in ("2024-11-05", "2025-11-25"):
            for text in ('{"entropy": NaN}', '{"count": 1, "count": 2}', 'not json', 'null'):
                with self.subTest(version=version, text=text):
                    with patch.object(mcp, "run_triage") as triage:
                        triage.return_value.model_dump_json.return_value = text
                        result = self.call("rea_triage", {"target_path": "unused"}, version)["result"]
                    self.assertTrue(result["isError"])
                    self.assertIn("invalid JSON", result["content"][0]["text"])

    def test_empty_decompilation_is_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.bin"
            path.write_bytes(b"not a Mach-O executable")
            with patch.object(mcp, "extract_function_cfg", return_value=[]):
                result = self.call("rea_decompile_cfg", {"binary_path": str(path)})["result"]
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["status"], "INCOMPLETE")
        self.assertEqual(result["structuredContent"]["reason"], "NO_FUNCTIONS_EXTRACTED")

    def test_synthesis_must_generate_actual_files(self):
        with tempfile.TemporaryDirectory() as directory:
            for files in ([], [Path(directory) / "not-created.py"]):
                with self.subTest(files=files):
                    with patch.object(mcp, "run_recreation", return_value=files):
                        result = self.call("rea_synthesize", {"evidence_path": "unused"})["result"]
                    self.assertTrue(result["isError"])


class ReportPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.evidence = self.root / "evidence.json"
        self.candidate = self.root / "candidate.py"
        self.report = self.root / "report.json"
        envelope = EvidenceEnvelopeV2(target=BinaryTriageReport("unused", "0" * 64, 0, "unknown", 0))
        self.evidence.write_text(envelope.model_dump_json())
        self.candidate.write_text("value = 1\n")
        self.report.write_text('{"previous": true}\n')

    def audit(self, report=None):
        return mcp.handle_tools_call(9, {"name": "rea_audit_parity", "arguments": {
            "evidence_path": str(self.evidence), "contract_path": str(self.candidate),
            "report_path": str(report or self.report)}})["result"]

    def test_invalid_backend_report_preserves_existing_report(self):
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        with patch.object(mcp, "audit_reconstruction", return_value={"status": "PASS", "bad": float("nan")}):
            result = self.audit()
        self.assertTrue(result["isError"])
        self.assertEqual({path.name: path.read_bytes() for path in self.root.iterdir()}, before)

    def test_failed_replace_preserves_existing_report_and_removes_temporary_file(self):
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        with patch.object(mcp, "audit_reconstruction", return_value={"status": "INCOMPLETE"}):
            with patch.object(mcp.os, "replace", side_effect=OSError("simulated disk failure")):
                result = self.audit()
        self.assertTrue(result["isError"])
        self.assertEqual({path.name: path.read_bytes() for path in self.root.iterdir()}, before)

    def test_failed_flush_preserves_existing_report_and_removes_temporary_file(self):
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        with patch.object(mcp, "audit_reconstruction", return_value={"status": "INCOMPLETE"}):
            with patch.object(mcp.os, "fsync", side_effect=OSError("simulated flush failure")):
                result = self.audit()
        self.assertTrue(result["isError"])
        self.assertEqual({path.name: path.read_bytes() for path in self.root.iterdir()}, before)

    def test_ambiguous_evidence_is_rejected_before_execution(self):
        original = self.evidence.read_text()
        for text in ('{"target":null,"target":{}}', '{"target":NaN}'):
            with self.subTest(text=text):
                self.evidence.write_text(text)
                with patch.object(mcp, "audit_reconstruction") as audit:
                    result = self.audit()
                    audit.assert_not_called()
                self.assertTrue(result["isError"])
                self.assertEqual(self.report.read_text(), '{"previous": true}\n')
        self.evidence.write_text(original)

    def test_unknown_backend_verdict_cannot_replace_the_report(self):
        with patch.object(mcp, "audit_reconstruction", return_value={"status": "SUCCESS"}):
            result = self.audit()
        self.assertTrue(result["isError"])
        self.assertEqual(self.report.read_text(), '{"previous": true}\n')

    def test_unwritable_destination_shape_is_rejected_before_audit(self):
        symlink = self.root / "linked.json"
        symlink.symlink_to(self.report)
        for destination in (self.root, self.root / "missing" / "report.json", symlink):
            with self.subTest(destination=destination):
                with patch.object(mcp, "audit_reconstruction", return_value={"status": "INCOMPLETE"}) as audit:
                    result = self.audit(destination)
                    audit.assert_not_called()
                self.assertTrue(result["isError"])

    def test_valid_report_matches_returned_summary_without_touching_inputs(self):
        before = (self.evidence.read_bytes(), self.candidate.read_bytes())
        verdict = {"status": "INCOMPLETE", "reason": "CONTRACT_ONLY", "cases": [{"number": 1}]}
        with patch.object(mcp, "audit_reconstruction", return_value=verdict):
            result = self.audit()
        self.assertTrue(result["isError"])
        self.assertEqual(json.loads(self.report.read_text()), verdict)
        self.assertEqual(result["structuredContent"]["report_path"], str(self.report.resolve()))
        self.assertNotIn("cases", result["structuredContent"])
        self.assertEqual((self.evidence.read_bytes(), self.candidate.read_bytes()), before)
        self.assertEqual({path.name for path in self.root.iterdir()},
                         {"evidence.json", "candidate.py", "report.json"})


class ProtocolHardeningTests(unittest.TestCase):
    def exchange(self, frames, command=None, env=None):
        wire = b"".join((item if isinstance(item, bytes)
                         else json.dumps(item).encode("utf-8")) + b"\n" for item in frames)
        completed = subprocess.run(
            command or [sys.executable, str(ROOT / "rea_mcp_server.py")],
            input=wire, capture_output=True, cwd=ROOT, env=env, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        return [json.loads(line) for line in completed.stdout.splitlines() if line.strip()], completed.stderr

    def test_batches_follow_the_revision_that_defined_them(self):
        for version in mcp.SUPPORTED_PROTOCOL_VERSIONS:
            with self.subTest(version=version):
                frames = handshake(version) + [[request("ping", 2), request("ping", 3)], request("ping", 4)]
                responses, _ = self.exchange(frames)
                self.assertEqual(responses[0]["result"]["protocolVersion"], version)
                self.assertEqual(responses[-1]["id"], 4)
                if version == "2025-03-26":
                    self.assertEqual([item["id"] for item in responses[1]], [2, 3])
                else:
                    self.assertNotIsInstance(responses[1], list)
                    self.assertEqual(responses[1]["error"]["code"], -32600)
                    self.assertNotIn(2, [item.get("id") for item in responses])

    def test_rejected_batch_does_not_run_initialize_or_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "ran"
            script = (
                "import rea_mcp_server as mcp\n"
                "from pathlib import Path\n"
                "def boom(path):\n"
                "    Path(path).write_text('ran')\n"
                "    raise RuntimeError('should not run')\n"
                "mcp.run_triage = boom\n"
                "mcp.main()\n"
            )
            init = request("initialize", 1, {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "rea-regression", "version": "1"},
            })
            batched = [init, request("tools/call", 2, {
                "name": "rea_triage", "arguments": {"target_path": str(marker)}})]
            responses, _ = self.exchange(
                [batched] + handshake("2025-11-25") + [request("ping", 3)],
                [sys.executable, "-c", script])
            self.assertFalse(marker.exists())
        self.assertEqual(responses[0]["error"]["code"], -32600)
        self.assertEqual(responses[1]["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(responses[2]["id"], 3)

    def test_accepted_batch_can_negotiate_and_omits_notifications(self):
        init, ready = handshake("2025-03-26")
        responses, _ = self.exchange([[init, ready, request("ping", 7)]])
        self.assertEqual(len(responses), 1)
        self.assertEqual([item["id"] for item in responses[0]], [1, 7])
        self.assertEqual(responses[0][0]["result"]["protocolVersion"], "2025-03-26")

    def test_notification_only_batch_is_silent(self):
        responses, _ = self.exchange(handshake("2025-03-26") + [[
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}]])
        self.assertEqual(len(responses), 1)

    def test_precancel_drops_the_request_and_initialize_is_protected(self):
        cancel = {"jsonrpc": "2.0", "method": "notifications/cancelled",
                  "params": {"requestId": 5, "reason": "stop"}}
        responses, stderr = self.exchange([cancel, request("ping", 5), request("ping", 6)])
        self.assertEqual([item["id"] for item in responses], [6])
        self.assertIn(b"Dropped cancelled request 5", stderr)
        init, _ = handshake()
        responses, stderr = self.exchange([
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}},
            init,
        ])
        self.assertEqual(responses[0]["result"]["protocolVersion"], "2025-11-25")
        self.assertIn(b"Ignored cancellation of initialize", stderr)

    def test_late_cancel_does_not_suppress_a_reused_id(self):
        responses, _ = self.exchange([
            request("ping", 5),
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 5}},
            request("ping", 5),
        ])
        self.assertEqual([item["id"] for item in responses], [5, 5])

    def test_stateless_revision_is_counter_offered_and_not_executed(self):
        responses, _ = self.exchange(handshake("2026-07-28"))
        self.assertEqual(responses[0]["result"]["protocolVersion"], "2025-11-25")
        responses, _ = self.exchange([request("server/discover", 3)])
        self.assertEqual(responses[0]["error"]["code"], -32601)
        self.assertIn("2026-07-28", responses[0]["error"]["message"])
        responses, _ = self.exchange(handshake() + [request("tools/list", 2, {
            "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}})])
        self.assertEqual(responses[1]["error"]["code"], -32602)
        self.assertIn("2025-11-25", responses[1]["error"]["data"]["supported"])
        self.assertNotIn("2026-07-28", responses[1]["error"]["data"]["supported"])

    def test_path_limits_urls_and_traversal_are_rejected_before_execution(self):
        cases = [
            ("rea_triage", {"target_path": "/tmp/../etc/passwd"}),
            ("rea_triage", {"target_path": "/tmp/bad\nname"}),
            ("rea_triage", {"target_path": "/" + ("a" * 5000)}),
            ("rea_reconstruct", {"output_directory": "/tmp/out", "original_argv": ["../bin/echo"]}),
            ("rea_reconstruct", {"output_directory": "/tmp/out", "original_argv": ["echo"] * 300}),
            ("rea_audit_parity", {"evidence_path": "evidence.json", "contract_path": "candidate.py",
                                  "seed": 2 ** 63}),
            ("rea_reconstruct_lmstudio", {
                "model_file": "model.gguf", "model_id": "local", "library": "lib.so",
                "headers": "include", "output_directory": "/tmp/out",
                "reference_url": "file:///etc/passwd"}),
        ]
        with patch.object(mcp, "_execute_tool") as execution:
            for name, arguments in cases:
                with self.subTest(name=name, arguments=arguments):
                    self.assertTrue(mcp.handle_tools_call(3, {"name": name, "arguments": arguments})["result"]["isError"])
            execution.assert_not_called()

    def test_generated_file_outside_the_output_directory_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            evidence.write_text("{}")
            outside = root / "outside.py"
            outside.write_text("value = 1\n")
            with patch.object(mcp, "run_recreation", return_value=[outside]):
                result = mcp.handle_tools_call(4, {"name": "rea_synthesize", "arguments": {
                    "evidence_path": str(evidence), "output_directory": str(root / "chosen"),
                }})["result"]
        self.assertTrue(result["isError"])
        self.assertIn("escaped", result["content"][0]["text"])

    def test_oversized_evidence_is_rejected_without_replacing_the_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, candidate, report = root / "evidence.json", root / "candidate.py", root / "report.json"
            evidence.write_text('{"keep": true, "pad": "' + ("x" * 80) + '"}')
            candidate.write_text("value = 1\n")
            report.write_text('{"previous": true}\n')
            with patch.object(mcp, "MAX_INPUT_FILE_BYTES", 32):
                with patch.object(mcp, "audit_reconstruction") as audit:
                    result = mcp.handle_tools_call(5, {"name": "rea_audit_parity", "arguments": {
                        "evidence_path": str(evidence), "contract_path": str(candidate),
                        "report_path": str(report),
                    }})["result"]
                    audit.assert_not_called()
            self.assertTrue(result["isError"])
            self.assertIn("byte input limit", result["content"][0]["text"])
            self.assertEqual(report.read_text(), '{"previous": true}\n')


SLOW_TOOL = """
import subprocess, sys, time
from pathlib import Path
import rea_mcp_server as mcp

def slow(path):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    Path(path).write_text(str(proc.pid))
    time.sleep(30)
    raise RuntimeError("tool was not stopped")

mcp.run_triage = slow
mcp.main()
"""


class StdioLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.stop()

    def spawn(self, env=None):
        merged = os.environ.copy()
        if env:
            merged.update(env)
        client = PipeClient([sys.executable, "-c", SLOW_TOOL], merged)
        self.clients.append(client)
        self.addCleanup(client.stop)
        return client

    def handshake(self, client, version="2025-11-25"):
        init, ready = handshake(version)
        client.send(init)
        response = client.read(5)
        self.assertEqual(response["result"]["protocolVersion"], version)
        client.send(ready)

    def test_sigterm_while_idle_exits_zero(self):
        client = self.spawn()
        client.send(request("ping", 1))
        self.assertEqual(client.read(5)["id"], 1)
        os.kill(client.proc.pid, signal.SIGTERM)
        self.assertEqual(client.proc.wait(timeout=3), 0)

    def test_stdin_eof_after_a_response_exits_zero(self):
        client = self.spawn()
        client.send(request("ping", 1))
        self.assertEqual(client.read(5)["id"], 1)
        client.close_stdin()
        self.assertEqual(client.proc.wait(timeout=3), 0)

    def test_inflight_cancel_kills_the_tool_group_and_sends_no_result(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "pid"
            client = self.spawn()
            self.handshake(client)
            client.send(request("tools/call", 8, {
                "name": "rea_triage", "arguments": {"target_path": str(marker)}}))
            grandchild = wait_for_pid(marker)
            client.send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                         "params": {"requestId": 8, "reason": "stop"}})
            client.send(request("ping", 9))
            response = client.read(5)
            self.assertEqual(response["id"], 9)
            self.assertFalse(client._buffer.strip())
            assert_dead(grandchild)
            client.close_stdin()
            self.assertEqual(client.proc.wait(timeout=3), 0)

    def test_tool_timeout_is_incomplete_and_kills_spawned_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "pid"
            client = self.spawn({"REA_MCP_TOOL_TIMEOUT_SECONDS": "2"})
            self.handshake(client)
            client.send(request("tools/call", 8, {
                "name": "rea_triage", "arguments": {"target_path": str(marker)}}))
            grandchild = wait_for_pid(marker)
            response = client.read(8)
            self.assertEqual(response["id"], 8)
            self.assertTrue(response["result"]["isError"])
            self.assertEqual(response["result"]["structuredContent"]["reason"], "TIMEOUT")
            assert_dead(grandchild)
            client.send(request("ping", 9))
            self.assertEqual(client.read(5)["id"], 9)
            client.close_stdin()
            self.assertEqual(client.proc.wait(timeout=3), 0)

    def test_sigterm_aborts_an_inflight_tool_group(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "pid"
            client = self.spawn()
            self.handshake(client)
            client.send(request("tools/call", 8, {
                "name": "rea_triage", "arguments": {"target_path": str(marker)}}))
            grandchild = wait_for_pid(marker)
            os.kill(client.proc.pid, signal.SIGTERM)
            self.assertEqual(client.proc.wait(timeout=3), 0)
            assert_dead(grandchild)


class PipeClient:
    def __init__(self, command, env):
        self.proc = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=ROOT, env=env, start_new_session=True)
        self._buffer = b""

    def send(self, message):
        raw = message if isinstance(message, bytes) else json.dumps(message).encode("utf-8")
        self.proc.stdin.write(raw + b"\n")
        self.proc.stdin.flush()

    def read(self, timeout):
        deadline = time.monotonic() + timeout
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("timed out waiting for a response: " + repr(self._buffer[:200]))
            with selectors.DefaultSelector() as selector:
                selector.register(self.proc.stdout, selectors.EVENT_READ)
                if not selector.select(remaining):
                    raise AssertionError("timed out waiting for a response: " + repr(self._buffer[:200]))
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            if chunk == b"":
                raise AssertionError("server closed stdout: " + repr(self._buffer[:200]))
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        return json.loads(line)

    def close_stdin(self):
        if self.proc.stdin is not None and not self.proc.stdin.closed:
            self.proc.stdin.close()

    def stop(self):
        if self.proc.poll() is None:
            self.close_stdin()
            try:
                os.kill(self.proc.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.kill(self.proc.pid, signal.SIGKILL)
                self.proc.wait(timeout=3)
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def wait_for_pid(path):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.is_file() and path.read_text().strip():
            return int(path.read_text().strip())
        time.sleep(0.02)
    raise AssertionError("tool did not record a child process")


def assert_dead(pid):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    raise AssertionError(f"process {pid} is still running")


if __name__ == "__main__":
    unittest.main()
