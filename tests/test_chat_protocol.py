"""Protocol comparison regressions; live model evidence is generated separately."""

import copy
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

from evidence_schema import BinaryTriageReport, EvidenceEnvelopeV2
from rea_auditor import audit_reconstruction
from rea_chat import BACKEND, NativeResourceMonitor, canonical_response, chat_cases, parse_sse
from rea_llm import native_program


class ChatProtocolTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'darwin', 'Uses the Darwin process resource API')
    def test_resource_monitor_measures_real_process_and_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'resources.jsonl'
            monitor = NativeResourceMonitor(os.getpid(), path)
            monitor.start()
            deadline = time.monotonic() + 2
            while monitor.samples == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            result = monitor.close()
            samples = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertFalse(monitor.thread.is_alive())
        self.assertGreater(result['samples'], 0)
        self.assertGreater(result['peak_physical_footprint_bytes'], 0)
        self.assertGreater(result['peak_resident_bytes'], 0)
        self.assertEqual(samples[0]['pid'], os.getpid())

    def test_native_execution_parameters_cannot_inject_source(self):
        for specification in ({'context_length': '1024; do_something()'},
                              {'context_length': 1024, 'gpu_layers': '0; do_something()'},
                              {'context_length': 0}, {'context_length': 1024, 'gpu_layers': -1}):
            with self.assertRaises(ValueError):
                native_program(specification)

    def event(self, delta, finish=None):
        return {'id': 'chatcmpl-1234567890', 'created': 1792591803,
                'object': 'chat.completion.chunk', 'model': 'local-model',
                'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish, 'logprobs': None}]}

    def response(self):
        return {'status': 200, 'content_type': 'text/event-stream', 'events': [
            self.event({'role': 'assistant', 'content': 'café'}),
            self.event({}, 'stop'), '[DONE]']}

    def test_only_identity_and_creation_time_are_normalized(self):
        original = self.response()
        changed = copy.deepcopy(original)
        for event in changed['events'][:-1]:
            event.update(id='chatcmpl-abcdefghij', created=1792591900)
        self.assertEqual(canonical_response(original), canonical_response(changed))
        changed['events'][0]['choices'][0]['delta']['content'] = 'different'
        self.assertNotEqual(canonical_response(original), canonical_response(changed))

    def test_changed_usage_finish_role_or_chunk_boundary_cannot_match(self):
        original = self.response()
        for change in ('finish', 'role', 'boundary', 'extra_field', 'missing_delta'):
            with self.subTest(change=change):
                changed = copy.deepcopy(original)
                if change == 'finish':
                    changed['events'][1]['choices'][0]['finish_reason'] = 'length'
                elif change == 'role':
                    changed['events'][0]['choices'][0]['delta']['role'] = 'user'
                elif change == 'boundary':
                    changed['events'][0]['choices'][0]['delta']['content'] = 'ca'
                    changed['events'].insert(1, self.event({'content': 'fé'}))
                elif change == 'extra_field':
                    changed['events'][0]['usage'] = {'completion_tokens': 1}
                else:
                    del changed['events'][0]
                self.assertNotEqual(canonical_response(original), canonical_response(changed))

    def test_identity_must_be_stable_inside_stream(self):
        changed = self.response()
        changed['events'][1]['id'] = 'chatcmpl-other-request'
        with self.assertRaisesRegex(ValueError, 'UNSTABLE_STREAM_IDENTITY'):
            canonical_response(changed)

    def test_strict_sse_requires_one_terminal_done(self):
        raw = 'data: ' + json.dumps(self.event({'content': 'é'})) + '\n\ndata: [DONE]\n\n'
        self.assertEqual(len(parse_sse(raw)), 2)
        for bad in (raw.replace('data: [DONE]\n\n', ''), raw + 'data: [DONE]\n\n',
                    raw + 'data: {}\n\n', 'event: token\n' + raw):
            with self.assertRaises(ValueError):
                parse_sse(bad)

    def test_chat_cannot_reuse_old_verdict_without_live_reference(self):
        evidence = EvidenceEnvelopeV2(
            target=BinaryTriageReport('unused', '0' * 64, 0, 'GGUF', None),
            clean_room_specification={'backend': BACKEND, 'reference_url': 'http://127.0.0.1:1234'},
        )
        self.assertEqual(audit_reconstruction(evidence, Path('unused.py'))['status'], 'INCOMPLETE')
        with tempfile.TemporaryDirectory() as directory:
            result = audit_reconstruction(evidence, Path(directory) / 'missing.py', manage_reference=True)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['lifecycle'], [])

    def test_cases_cover_both_protocols_and_fresh_conversation_memory(self):
        first, second = chat_cases('local-model', 1), chat_cases('local-model', 2)
        self.assertNotEqual(first, second)
        self.assertEqual(sum(r['stream'] for r in first), len(first) // 2)
        self.assertTrue(any('stop' in r for r in first))
        self.assertTrue(any(len(r['messages']) > 2 for r in first))
        self.assertEqual(first[:2], first[-2:])
