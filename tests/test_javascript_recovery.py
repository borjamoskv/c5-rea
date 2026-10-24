"""Compiler unit inputs; these fixtures are never application parity evidence."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from rea_javascript import recover_javascript

TOOLS = os.environ.get('C5_REA_JS_TOOLCHAIN')


class RecoveryInputGuards(unittest.TestCase):
    def test_output_cannot_overwrite_original_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, 'DISJOINT'):
                recover_javascript(tmp, Path(tmp) / 'generated', tmp)


@unittest.skipUnless(TOOLS and shutil.which('node'), 'Explicit Babel build toolchain required')
class JavascriptCompilerTests(unittest.TestCase):
    def recover(self, body, *, first='value0'):
        values = [first] + ['value'+str(i) for i in range(1, 20)]
        source = '''function table(){const a=VALUES;table=function(){return a};return table()}
function decode(n){const a=table();return decode=function(i){return a[i]},decode(n)}
(function(get,end){const a=get();while(true){a['push'](a['shift']());a['unshift'](a['pop']());break}})(table,1);
'''.replace('VALUES', json.dumps(values)) + body
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / 'original.js'
            original.write_text(source)
            result = recover_javascript(original, root / 'out', TOOLS)
            candidate = root / 'out/generated/original.js'
            expected = subprocess.run(['node', str(original)], capture_output=True, timeout=10)
            actual = subprocess.run(['node', str(candidate)], capture_output=True, timeout=10)
            self.assertEqual(expected.returncode, 0, expected.stderr)
            self.assertEqual((expected.returncode, expected.stdout, expected.stderr),
                             (actual.returncode, actual.stdout, actual.stderr))
            self.assertEqual(result['status'], 'INCOMPLETE')
            self.assertFalse(result['ui_verified'])
            self.assertFalse(result['api_verified'])
            return result['files'][0]

    def test_real_rotation_syntax_and_constant_alias_are_recovered(self):
        result = self.recover('const alias=decode; console.log(alias(2), decode(3));')
        self.assertTrue(result['pure_bootstrap_recognized'])
        self.assertEqual(result['folded_decoder_calls'], 2)
        self.assertEqual(result['distinct_decoder_arguments_checked'], 2)
        self.assertTrue(result['syntax_checked'])

    def test_decoder_used_as_a_computed_property_is_a_read(self):
        result = self.recover('const obj={};obj[decode(0)]=123;console.log(obj.value0);')
        self.assertEqual(result['folded_decoder_calls'], 1)

    def test_mutable_alias_is_not_folded(self):
        for mutation in ['alias=()=>"changed";', '[alias]=[()=>"changed"];',
                         'for(alias of [()=>"changed"]){}']:
            with self.subTest(mutation=mutation):
                result = self.recover('let alias=decode; '+mutation+'console.log(alias(0));')
                self.assertEqual(result['folded_decoder_calls'], 0)

    def test_block_shadowing_cannot_resolve_to_global_decoder(self):
        result = self.recover('function f(){ {const decode=()=>"shadow"; console.log(decode(0));} }f();')
        self.assertEqual(result['folded_decoder_calls'], 0)

    def test_escaped_table_and_replaced_decoder_fail_closed(self):
        for body in ['table()[0]="changed";console.log(decode(0));',
                     'decode=()=>"changed";console.log(decode(0));']:
            with self.subTest(body=body):
                result = self.recover(body)
                self.assertFalse(result['pure_bootstrap_recognized'])
                self.assertEqual(result['folded_decoder_calls'], 0)

    def test_dynamic_eval_disables_folding_but_read_only_literal_does_not(self):
        static = self.recover('eval("table;");console.log(decode(0));')
        self.assertEqual(static['folded_decoder_calls'], 1)
        dynamic = self.recover('const code="decode=()=>\\"changed\\"";eval(code);console.log(decode(0));')
        self.assertEqual(dynamic['folded_decoder_calls'], 0)

    def test_literal_does_not_create_a_strict_mode_directive(self):
        result = self.recover('function f(){decode(0);return this===undefined}console.log(f());', first='use strict')
        self.assertEqual(result['folded_decoder_calls'], 1)


@unittest.skipUnless(shutil.which('node'), 'Requires Node.js runtime')
class JavascriptLiveHarnessTests(unittest.TestCase):
    def test_live_handler_verification_pass(self):
        from rea_javascript import verify_js_handlers_live
        from evidence_schema import EvidenceEnvelopeV2, BinaryTriageReport
        from rea_auditor import audit_reconstruction

        orig_js = """
        function handleIpc(channel, payload) {
            if (channel === 'calc:add') return { sum: payload.a + payload.b };
            if (channel === 'calc:echo') return { text: payload.msg };
            throw new Error('UNKNOWN_CHANNEL');
        }
        module.exports = { handleIpc };
        """
        cand_js = orig_js  # Identical behavioral implementation

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            orig_file = p / 'orig.js'
            cand_file = p / 'cand.js'
            orig_file.write_text(orig_js)
            cand_file.write_text(cand_js)

            cases = [
                {'channel': 'calc:add', 'payload': {'a': 5, 'b': 7}},
                {'channel': 'calc:echo', 'payload': {'msg': 'hello world'}},
                {'channel': 'unknown:ch', 'payload': {}}
            ]

            # Direct harness execution
            result = verify_js_handlers_live(orig_file, cand_file, cases)
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['verified_cases'], 3)
            self.assertEqual(result['coverage_percent'], 100.0)

            # Integration with rea_auditor.audit_reconstruction
            envelope = EvidenceEnvelopeV2(
                target=BinaryTriageReport(str(orig_file), '0'*64, 100, 'js', 0),
                clean_room_specification={
                    'backend': 'javascript-ipc-handler-v1',
                    'original_module': str(orig_file),
                    'test_cases': cases
                }
            )
            audit = audit_reconstruction(envelope, cand_file)
            self.assertEqual(audit['status'], 'PASS')
            self.assertEqual(audit['reason'], 'LIVE_DIFFERENTIAL_MATCH')

    def test_live_handler_verification_detects_divergence(self):
        from rea_javascript import verify_js_handlers_live

        orig_js = "module.exports = { handleIpc: (ch, p) => ({ res: p.x * 2 }) };"
        cand_js = "module.exports = { handleIpc: (ch, p) => ({ res: p.x * 3 }) };"

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            orig_file = p / 'orig.js'
            cand_file = p / 'cand.js'
            orig_file.write_text(orig_js)
            cand_file.write_text(cand_js)

            cases = [{'channel': 'math:op', 'payload': {'x': 10}}]
            result = verify_js_handlers_live(orig_file, cand_file, cases)
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['reason'], 'OUTPUT_DIVERGENCE_DETECTED')


if __name__ == '__main__':
    unittest.main()
