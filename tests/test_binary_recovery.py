"""Compiler safety checks. Real application differential reports are separate."""

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rea_lift import (UnsupportedBinary, audit_binary, execute_case, generate_binary,
                      generate_c, inspect_binary, macho_image, recover_ir, sha,
                      translated_statements)


class InstructionRecoveryTests(unittest.TestCase):
    def test_unknown_instruction_and_unresolved_branch_fail_closed(self):
        for instruction in ({'address': 0, 'op': 'svc', 'args': ['#0']},
                            {'address': 0, 'op': 'b', 'args': ['0x100']},
                            {'address': 0, 'op': 'mov', 'args': ['x0; injected()', '#0']}):
            with self.subTest(instruction=instruction):
                with self.assertRaises(UnsupportedBinary):
                    translated_statements(instruction, {0}, {'functions': {}})

    def test_arbitrary_file_is_not_accepted_as_machine_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad'
            path.write_bytes(b'not a native application')
            with self.assertRaises(UnsupportedBinary):
                macho_image(path)


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('otool'), 'Requires Apple binary tools')
class RealBinaryRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = inspect_binary('/usr/bin/rev')

    @unittest.skipUnless(Path('/Applications/LM Studio.app/Contents/MacOS/LM Studio').is_file(), 'Requires the installed original')
    def test_pc_relative_literals_in_actual_electron_launcher(self):
        original = Path('/Applications/LM Studio.app/Contents/MacOS/LM Studio')
        image = macho_image(original)
        recovered = recover_ir(original)
        relative = [i for i in recovered['instructions'] if i['op'] == 'adr' and 'literal' in i]
        self.assertGreater(len(relative), 0)
        for instruction in relative:
            address = instruction['address'] + int(instruction['args'][1].lstrip('#'), 0)
            self.assertIn(address, image['strings'])
            self.assertEqual(instruction['literal'], 's_' + format(address, 'x'))

    def test_recovery_does_not_select_implementation_by_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'unfamiliar_application_91734'
            shutil.copyfile('/usr/bin/rev', path)
            other = inspect_binary(path)
        first = self.evidence.clean_room_specification
        second = other.clean_room_specification
        self.assertEqual(first['ir'], second['ir'])
        self.assertEqual(generate_c(first['ir'], first['abi']), generate_c(second['ir'], second['abi']))

    def test_deleting_application_flag_cannot_enable_cli_only_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'Example.app/Contents/MacOS/rev'
            original.parent.mkdir(parents=True)
            shutil.copyfile('/usr/bin/rev', original)
            evidence = inspect_binary(original)
            evidence.clean_room_specification.pop('requires_application_verification')
            binary, _ = generate_binary(evidence, root / 'candidate')
            result = audit_binary(evidence, binary)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['reason'], 'APPLICATION_UI_AND_API_VERIFICATION_REQUIRED')
        self.assertEqual(result['verified_cases'], 0)

    def test_forged_instruction_evidence_cannot_pass(self):
        evidence = copy.deepcopy(self.evidence)
        evidence.clean_room_specification['ir']['instructions'][0]['op'] = 'nop'
        result = audit_binary(evidence, '/nonexistent/rev')
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['reason'], 'IR_OR_ABI_NOT_DERIVED_FROM_ORIGINAL')

    def test_updated_binary_hash_cannot_certify_unrelated_code(self):
        evidence = copy.deepcopy(self.evidence)
        with tempfile.TemporaryDirectory() as directory:
            binary, recovered = generate_binary(evidence, directory)
            unrelated = Path(directory) / 'unrelated.c'
            unrelated.write_text('int main(void) { return 0; }\n')
            subprocess.run(['clang', str(unrelated), '-o', str(binary)], check=True, capture_output=True)
            evidence.clean_room_specification['implementation_sha256'] = sha(binary)
            result = audit_binary(evidence, binary)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['reason'], 'EXECUTABLE_TEXT_NOT_COMPILED_FROM_RECOVERED_SOURCE')

    def test_live_process_comparison_detects_changed_native_instruction(self):
        evidence = copy.deepcopy(self.evidence)
        spec = evidence.clean_room_specification
        # Change the first conditional branch without writing an application.
        branch = next(i for i in spec['ir']['instructions'] if i['op'] == 'b.ne')
        branch['op'] = 'b.eq'
        with tempfile.TemporaryDirectory() as directory:
            binary, source = generate_binary(evidence, directory)
            case = {'argv': [], 'stdin': 'YWJjCg==', 'files': {}, 'locale': 'C'}
            original = execute_case('/usr/bin/rev', case)
            changed = execute_case(binary, case)
        self.assertNotEqual(original, changed)
        self.assertEqual(original['returncode'], 0)
        self.assertNotEqual(original['stdout'], changed['stdout'])

    def test_negative_32_bit_native_return_clears_upper_register_bits(self):
        evidence = copy.deepcopy(self.evidence)
        spec = evidence.clean_room_specification
        operations = [('mov', ['x19', 'x30']), ('mov', ['w0', '#1']),
                      ('mov', ['x2', '#0']), ('bl', ['0']),
                      ('cmp', ['x0', '#0xffffffff']), ('cset', ['w0', 'ne']),
                      ('mov', ['x30', 'x19']), ('ret', [])]
        instructions = [{'address': 4096+i*4, 'op': op, 'args': args} for i, (op, args) in enumerate(operations)]
        instructions[2]['literal'] = 's_0'
        instructions[3]['import'] = 'getopt'
        spec['ir'] = {'entry': 4096, 'instructions': instructions, 'literals': {'s_0': ''}}
        with tempfile.TemporaryDirectory() as directory:
            binary, source = generate_binary(evidence, directory)
            result = execute_case(binary, {'argv': [], 'stdin': '', 'files': {}, 'locale': 'C'})
        self.assertEqual(result['returncode'], 0)


if __name__ == '__main__':
    unittest.main()
