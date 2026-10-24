"""Static ARM64 Mach-O -> C translation, with independent live falsification.

The application is never selected by name. Instructions, branches, literals and
imported ABI types determine emitted statements. Unknown instructions/imports
stop translation. No target source, target executable bytes or oracle responses
are embedded in the new program. This is a bounded binary translator, not a
universal decompiler or a claim of recovering original high-level source.
"""

import base64
import hashlib
import json
import os
import random
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from evidence_schema import BinaryTriageReport, EvidenceEnvelopeV2


BACKEND = 'static-arm64-macho-c-v1'
HEADERS = ('stdio.h', 'stdlib.h', 'stdint.h', 'string.h', 'unistd.h',
           'locale.h', 'wchar.h', 'err.h', 'errno.h', 'sys/stat.h', 'stdbool.h')


class UnsupportedBinary(ValueError):
    """Translation cannot account for the complete selected instruction section."""


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def command_output(arguments):
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(arguments, stdout=output, stderr=errors, timeout=60)
        output.seek(0); errors.seek(0)
        if result.returncode:
            raise UnsupportedBinary(errors.read().decode(errors='replace'))
        return output.read().decode()


def macho_image(path):
    data = Path(path).read_bytes()
    if data[:4] == b'\xca\xfe\xba\xbe':
        count = struct.unpack_from('>I', data, 4)[0]
        slices = [struct.unpack_from('>IIIII', data, 8 + i * 20) for i in range(count)]
        arm = next((s for s in slices if s[0] == 0x100000c), None)
        if arm is None:
            raise UnsupportedBinary('NO_ARM64_SLICE')
        data = data[arm[2]:arm[2] + arm[3]]
    if len(data) < 32 or data[:4] != b'\xcf\xfa\xed\xfe':
        raise UnsupportedBinary('ONLY_64_BIT_LITTLE_ENDIAN_MACHO_SUPPORTED')
    _, cpu, subtype, filetype, count, size, flags, reserved = struct.unpack_from('<8I', data)
    if cpu != 0x100000c or filetype != 2 or count > 1024:
        raise UnsupportedBinary('ONLY_ARM64_EXECUTABLES_SUPPORTED')
    sections, entry, text_base = [], None, None
    offset = 32
    for _ in range(count):
        cmd, length = struct.unpack_from('<II', data, offset)
        if length < 8 or offset + length > min(len(data), 32 + size):
            raise UnsupportedBinary('INVALID_LOAD_COMMAND')
        if cmd == 0x19:
            segment = struct.unpack_from('<II16sQQQQiiII', data, offset)
            if segment[2].rstrip(b'\0') == b'__TEXT':
                text_base = segment[3]
            for i in range(segment[9]):
                raw = struct.unpack_from('<16s16sQQIIIIIIII', data, offset + 72 + i * 80)
                sections.append({'name': raw[0].rstrip(b'\0').decode(),
                                 'segment': raw[1].rstrip(b'\0').decode(),
                                 'address': raw[2], 'size': raw[3], 'offset': raw[4]})
        if cmd == 0x80000028:
            entry = struct.unpack_from('<Q', data, offset + 8)[0]
        offset += length
    if entry is None or text_base is None:
        raise UnsupportedBinary('MAIN_ENTRY_MISSING')
    code = next(s for s in sections if s['name'] == '__text')
    # Parse only semantic literal sections. Never embed executable/data images.
    strings = {}
    for section in sections:
        if section['name'] != '__cstring':
            continue
        raw = data[section['offset']:section['offset'] + section['size']]
        for start in range(len(raw)):
            end = raw.find(b'\0', start)
            if end >= 0:
                strings[section['address'] + start] = raw[start:end]
    return {'architecture': 'arm64e' if subtype & 0xffffff == 2 else 'arm64',
            'entry': text_base + entry, 'text_address': code['address'],
            'text_size': code['size'], 'strings': strings}


def split_operands(text):
    return [s.strip() for s in re.split(r',\s*(?![^\[]*\])', text) if s.strip()]


def recover_ir(path):
    image = macho_image(path)
    listing = command_output(['otool', '-arch', image['architecture'], '-tvV', str(path)])
    instructions, literals, imports, globals_ = [], {}, set(), set()
    pages = {}
    for line in listing.splitlines():
        match = re.match(r'^([0-9a-fA-F]{16})\s+([a-z0-9.]+)(?:\s+(.*))?$', line)
        if not match:
            continue
        address = int(match[1], 16)
        if not image['text_address'] <= address < image['text_address'] + image['text_size']:
            continue
        rest = match[3] or ''
        operands, _, comment = rest.partition(';')
        args = split_operands(operands)
        instruction = {'address': address, 'op': match[2], 'args': args}
        if match[2] == 'adrp':
            page = re.search(r'0x[0-9a-fA-F]+', comment)
            if not page:
                raise UnsupportedBinary('ADRP_TARGET_NOT_RESOLVED')
            pages[args[0]] = int(page[0], 16)
        if 'literal pool for:' in comment:
            if match[2] == 'adr' and len(args) == 2:
                # ADR is relative to this instruction, not to its page and
                # not to the current file offset. Apple's linker commonly
                # relaxes ADRP+ADD into ADR+NOP in Electron launchers.
                literal_address = address + int(args[1].lstrip('#'), 0)
            elif match[2] == 'add' and len(args) == 3 and args[1] in pages:
                literal_address = pages[args[1]] + int(args[2].lstrip('#'), 0)
            else:
                raise UnsupportedBinary('UNRESOLVED_LITERAL')
            if literal_address not in image['strings']:
                raise UnsupportedBinary('LITERAL_OUTSIDE_CSTRING')
            identifier = 's_' + format(literal_address, 'x')
            literals[identifier] = base64.b64encode(image['strings'][literal_address]).decode()
            instruction['literal'] = identifier
        imported = re.search(r'symbol stub for:\s*(_[A-Za-z0-9_]+)', comment)
        global_ = re.search(r'literal pool symbol address:\s*(_[A-Za-z0-9_]+)', comment)
        if imported:
            instruction['import'] = imported[1][1:]
            imports.add(instruction['import'])
        if global_:
            instruction['global'] = global_[1][1:]
            globals_.add(instruction['global'])
        instructions.append(instruction)
    expected = list(range(image['text_address'], image['text_address'] + image['text_size'], 4))
    if [i['address'] for i in instructions] != expected:
        raise UnsupportedBinary('INCOMPLETE_TEXT_DISASSEMBLY')
    return {'architecture': image['architecture'], 'entry': image['entry'],
            'instructions': instructions, 'literals': literals,
            'imports': sorted(imports), 'globals': sorted(globals_)}


def recover_abi(imports, globals_, public_abi=None):
    includes = ''.join('#include <' + header + '>\n' for header in HEADERS)
    public_abi = public_abi or {}
    for header in public_abi.get('headers', []):
        if sha(header['path']) != header['sha256']:
            raise UnsupportedBinary('PUBLIC_ABI_HEADER_CHANGED')
        includes += '#include ' + json.dumps(header['path']) + '\n'
    for declaration in public_abi.get('declarations', []):
        if hashlib.sha256(declaration['text'].encode()).hexdigest() != declaration['sha256']:
            raise UnsupportedBinary('PUBLIC_ABI_DECLARATION_CHANGED')
        includes += declaration['text'] + '\n'
    with tempfile.TemporaryDirectory(prefix='c5-abi-') as directory:
        source = Path(directory) / 'abi.c'
        source.write_text(includes)
        language = ['-x', 'c++', '-std=c++17'] if public_abi else []
        tree = json.loads(command_output(['clang', *language, '-Xclang', '-ast-dump=json', '-fsyntax-only', str(source)]))
    functions, variables = {}, {}
    pending = list(tree.get('inner', []))
    while pending:
        node = pending.pop()
        name, kind = node.get('name'), node.get('kind')
        mangled = node.get('mangledName', '')
        candidates = (name, mangled, mangled[1:] if mangled.startswith('_') else None)
        key = next((candidate for candidate in candidates if candidate in imports), None)
        if key in imports and kind == 'FunctionDecl':
            functions[key] = {'type': node['type']['qualType'],
                               'parameters': [p['type']['qualType'] for p in node.get('inner', []) if p['kind'] == 'ParmVarDecl'],
                               'variadic': node.get('variadic', False)}
        if name in globals_ and kind == 'VarDecl':
            variables[name] = node['type']['qualType']
        if kind in ('NamespaceDecl', 'LinkageSpecDecl', 'TranslationUnitDecl'):
            pending.extend(node.get('inner', []))
    if set(functions) != set(imports) or set(variables) != set(globals_):
        raise UnsupportedBinary('IMPORT_WITHOUT_PUBLIC_ABI: ' + repr((set(imports)-set(functions)) | (set(globals_)-set(variables))))
    for function in functions.values():
        if len(function['parameters']) > 8 or any(re.search(r'\b(float|double)\b|\(\*|\.\.\.', p) for p in function['parameters']):
            raise UnsupportedBinary('UNSUPPORTED_NATIVE_CALL_ABI')
    result = {'headers': list(HEADERS), 'functions': functions, 'globals': variables}
    if public_abi:
        result['public_abi'] = public_abi
    return result


def reg(value):
    if value in ('xzr', 'wzr'):
        return 'UINT64_C(0)'
    if value == 'sp':
        return 'sp'
    if re.fullmatch(r'[qv](?:[12]?[0-9]|3[01])', value):
        return 'v[' + value[1:] + ']'
    if re.fullmatch(r'[xw](?:[12]?[0-9]|30)', value):
        read = 'x[' + value[1:] + ']'
        return '(uint32_t)' + read if value[0] == 'w' else read
    if re.fullmatch(r'#?-?(?:0x[0-9a-f]+|[0-9]+)', value):
        number = int(value.lstrip('#'), 0)
        return str(number) if number < 0 else 'UINT64_C(' + str(number) + ')'
    raise UnsupportedBinary('UNSUPPORTED_OPERAND: ' + value)


def write_reg(destination, expression):
    if destination in ('xzr', 'wzr'):
        return '(void)(' + expression + ');'
    if destination == 'sp':
        return 'sp = ' + expression + ';'
    if re.fullmatch(r'[qv](?:[12]?[0-9]|3[01])', destination):
        return reg(destination) + ' = (uint128_t)(' + expression + ');'
    reg(destination)  # validate destination before emitting code
    return 'x[' + destination[1:] + '] = ' + ('(uint32_t)' if destination[0] == 'w' else '(uint64_t)') + '(' + expression + ');'


def memory_operand(text, trailing):
    match = re.fullmatch(r'\[([^\]]+)\](!?)', text)
    if not match:
        raise UnsupportedBinary('UNSUPPORTED_MEMORY_OPERAND: ' + text)
    parts = split_operands(match[1])
    base = parts[0]
    delta = reg(parts[1]) if len(parts) > 1 else '0'
    if len(parts) > 2:
        shift = re.fullmatch(r'lsl #([0-9]+)', parts[2])
        if not shift:
            raise UnsupportedBinary('UNSUPPORTED_ADDRESS_MODIFIER')
        delta = '(' + delta + ' << ' + shift[1] + ')'
    if len(parts) > 3 or len(trailing) > 1 or (match[2] and trailing):
        raise UnsupportedBinary('UNSUPPORTED_INDEXING')
    before = write_reg(base, reg(base) + ' + ' + delta) if match[2] else ''
    address = reg(base) if match[2] else '(' + reg(base) + ' + ' + delta + ')'
    after = write_reg(base, reg(base) + ' + ' + reg(trailing[0])) if trailing else ''
    return before, address, after


CONDITIONS = {'eq': 'Z', 'ne': '!Z', 'hs': 'C', 'cs': 'C', 'lo': '!C', 'cc': '!C',
              'hi': '(C && !Z)', 'ls': '(!C || Z)', 'ge': '(N == V)', 'lt': '(N != V)',
              'gt': '(!Z && N == V)', 'le': '(Z || N != V)', 'mi': 'N', 'pl': '!N'}


def translated_statements(instruction, addresses, abi):
    op, args = instruction['op'], instruction['args']
    following = instruction['address'] + 4
    def branch(value):
        address = int(value, 0)
        if address not in addresses:
            raise UnsupportedBinary('BRANCH_OUTSIDE_RECOVERED_TEXT')
        return 'goto L_' + format(address, 'x') + ';'
    if op in ('nop', 'pacibsp', 'paciasp', 'autibsp', 'autiasp'):
        return ['; /* architectural integrity hint; native compiler protects the new stack */']
    if op == 'adrp':
        return [write_reg(args[0], hex(int(args[1], 0) * 4096 + (instruction['address'] & ~4095)))]
    if instruction.get('literal'):
        return [write_reg(args[0], '(uintptr_t)' + instruction['literal'])]
    if instruction.get('global'):
        return [write_reg(args[0], '(uintptr_t)&' + instruction['global'])]
    if op == 'adr':
        if len(args) != 2:
            raise UnsupportedBinary('INVALID_PC_RELATIVE_ADDRESS')
        return [write_reg(args[0], str(instruction['address'] + int(args[1].lstrip('#'), 0)))]
    if op == 'movi.16b':
        value = int(args[1].lstrip('#'), 0)
        if len(args) != 2 or not 0 <= value <= 255:
            raise UnsupportedBinary('UNSUPPORTED_VECTOR_IMMEDIATE')
        half = int.from_bytes(bytes([value]) * 8, 'little')
        return [write_reg(args[0], '((uint128_t)UINT64_C(' + str(half) + ') << 64) | UINT64_C(' + str(half) + ')')]
    if op in ('mov', 'movz'):
        if len(args) != 2:
            raise UnsupportedBinary('SHIFTED_MOVE_NOT_SUPPORTED')
        return [write_reg(args[0], reg(args[1]))]
    if op in ('adds', 'subs'):
        if len(args) != 3:
            raise UnsupportedBinary('SHIFTED_FLAG_ARITHMETIC_NOT_SUPPORTED')
        compare = {**instruction, 'op': 'cmn' if op == 'adds' else 'cmp', 'args': args[1:]}
        return translated_statements(compare, addresses, abi) + [write_reg(args[0], 'R')]
    if op in ('csel', 'cset'):
        condition = CONDITIONS.get(args[-1])
        if condition is None:
            raise UnsupportedBinary('UNSUPPORTED_SELECT_CONDITION')
        expression = '(' + condition + ') ? ' + (reg(args[1]) + ' : ' + reg(args[2]) if op == 'csel' else '1 : 0')
        return [write_reg(args[0], expression)]
    if op in ('add', 'sub', 'and', 'orr', 'eor'):
        right = reg(args[2])
        if len(args) == 4:
            shift = re.fullmatch(r'(lsl|uxtw|sxtw)(?: #([0-9]+))?', args[3])
            if not shift:
                raise UnsupportedBinary('UNSUPPORTED_ARITHMETIC_SHIFT')
            if shift[1] in ('uxtw', 'sxtw'):
                right = ('(uint64_t)(int64_t)(int32_t)' if shift[1] == 'sxtw' else '(uint32_t)') + '(' + right + ')'
            right = '(' + right + ' << ' + (shift[2] or '0') + ')'
        if len(args) not in (3, 4):
            raise UnsupportedBinary('INVALID_ARITHMETIC')
        operator = {'add': '+', 'sub': '-', 'and': '&', 'orr': '|', 'eor': '^'}[op]
        return [write_reg(args[0], reg(args[1]) + ' ' + operator + ' ' + right)]
    if op in ('cmp', 'cmn'):
        bits = 32 if args[0].startswith('w') else 64
        mask = 'UINT32_MAX' if bits == 32 else 'UINT64_MAX'
        result = '(A + B)' if op == 'cmn' else '(A - B)'
        carry = '(R < A)' if op == 'cmn' else '(A >= B)'
        if op == 'cmn' and bits == 32:
            carry = '(A + B > UINT32_MAX)'
        overflow = '(~(A ^ B) & (A ^ R))' if op == 'cmn' else '((A ^ B) & (A ^ R))'
        return ['A = (' + reg(args[0]) + ') & ' + mask + '; B = (' + reg(args[1]) + ') & ' + mask + ';',
                'R = ' + result + ' & ' + mask + '; Z = R == 0; N = R >> ' + str(bits-1) + '; C = ' + carry + '; V = (' + overflow + ' >> ' + str(bits-1) + ') & 1;']
    if op.startswith('b.'):
        condition = CONDITIONS.get(op[2:])
        if condition is None:
            raise UnsupportedBinary('UNSUPPORTED_CONDITION')
        return ['if (' + condition + ') { ' + branch(args[0]) + ' }']
    if op in ('cbz', 'cbnz'):
        return ['if (' + reg(args[0]) + (' == 0' if op == 'cbz' else ' != 0') + ') { ' + branch(args[1]) + ' }']
    if op in ('tbz', 'tbnz'):
        bit = int(args[1].lstrip('#'), 0)
        if not 0 <= bit < (32 if args[0].startswith('w') else 64):
            raise UnsupportedBinary('INVALID_BIT_TEST')
        return ['if (((' + reg(args[0]) + ' >> ' + str(bit) + ') & 1)' + (' == 0' if op == 'tbz' else ' != 0') + ') { ' + branch(args[2]) + ' }']
    if op == 'b' and not instruction.get('import'):
        return [branch(args[0])]
    if op in ('bl', 'b'):
        if not instruction.get('import'):
            return [write_reg('x30', str(following)), branch(args[0])]
        name = instruction['import']
        function = abi['functions'][name]
        params = ['(' + kind + ')(uintptr_t)x[' + str(i) + ']' for i, kind in enumerate(function['parameters'])]
        if function['variadic']:
            # Darwin ARM64 varargs are passed on the caller stack, not x registers.
            # Integer/pointer arguments only; floating/aggregate variadics rejected.
            params.extend('load64(sp + ' + str(i*8) + ')' for i in range(8))
        expression = name + '(' + ', '.join(params) + ')'
        return_type = function['type'].split('(', 1)[0].strip()
        # A 32-bit native result writes W0 and clears X0's upper half, even
        # when C's signed result would otherwise sign-extend to uint64_t.
        if return_type == 'void':
            statement = expression + ';'
        else:
            result = '(sizeof(' + return_type + ') <= 4 ? (uint64_t)(uint32_t)(uintptr_t)(' + expression + ') : (uint64_t)(uintptr_t)(' + expression + '))'
            statement = write_reg('x0', result)
        if op == 'b':
            return [statement, 'if (x[30] == 0) return (int)x[0];', 'target = x[30]; goto indirect_return;']
        return [write_reg('x30', str(following)), statement]
    if op in ('ret', 'retab', 'retaa'):
        return ['if (x[30] == 0) return (int)x[0];', 'target = x[30]; goto indirect_return;']
    if op in ('br', 'braaz', 'brabz'):
        register = args[0] if op == 'br' else ('x' + args[0][1:] if args[0].startswith('x') else args[0])
        return ['target = ' + reg(register) + ';', 'goto indirect_return;']
    if op in ('blr', 'blraaz', 'blrabz'):
        register = args[0] if op == 'blr' else ('x' + args[0][1:] if args[0].startswith('x') else args[0])
        return [write_reg('x30', str(following)), 'target = ' + reg(register) + ';', 'goto indirect_return;']
    if op in ('ldr', 'ldur', 'ldrsw', 'ldrb', 'ldrh', 'str', 'stur', 'strb', 'strh', 'ldp', 'stp'):
        pair = op in ('ldp', 'stp')
        count = 2 if pair else 1
        before, address, after = memory_operand(args[count], args[count+1:])
        result = [before] if before else []
        result.append('address = ' + address + ';')
        for i, destination in enumerate(args[:count]):
            width = 128 if destination.startswith('q') else (16 if op in ('ldrh', 'strh') else (8 if op in ('ldrb', 'strb') else (32 if destination.startswith('w') or op == 'ldrsw' else 64)))
            location = '(address + ' + str(i * (width // 8)) + ')'
            if op.startswith('st'):
                result.append('store' + str(width) + '(' + location + ', ' + reg(destination) + ');')
            else:
                value = 'load' + str(width) + '(' + location + ')'
                if op == 'ldrsw':
                    value = '(int64_t)(int32_t)' + value
                result.append(write_reg(destination, value))
        if after:
            result.append(after)
        return result
    raise UnsupportedBinary('UNSUPPORTED_INSTRUCTION: ' + op + ' at ' + hex(instruction['address']))


def generate_c(ir, abi):
    addresses = {i['address'] for i in ir['instructions']}
    if len(addresses) != len(ir['instructions']) or ir['entry'] not in addresses:
        raise UnsupportedBinary('INVALID_INSTRUCTION_ADDRESSES')
    lines = ['/* Generated from recovered instructions. No application-specific implementation. */']
    lines += ['#include <' + h + '>' for h in HEADERS]
    lines.append('typedef unsigned __int128 uint128_t;')
    if abi.get('public_abi'):
        for name, function in sorted(abi['functions'].items()):
            if not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name):
                raise UnsupportedBinary('INVALID_ABI_SYMBOL_NAME')
            parameters = function['parameters'] + (['...'] if function['variadic'] else [])
            lines.append('extern ' + function['type'].split('(', 1)[0].strip() + ' ' + name + '(' + (', '.join(parameters) or 'void') + ');')
    for bits in (8, 16, 32, 64, 128):
        lines.append('static uint' + str(bits) + '_t load' + str(bits) + '(uintptr_t p) { uint' + str(bits) + '_t v; memcpy(&v, (void *)p, sizeof v); return v; }')
        lines.append('static void store' + str(bits) + '(uintptr_t p, uint' + str(bits) + '_t v) { memcpy((void *)p, &v, sizeof v); }')
    for name, encoded in sorted(ir['literals'].items()):
        if not re.fullmatch(r's_[0-9a-f]+', name):
            raise UnsupportedBinary('INVALID_LITERAL_NAME')
        literal = ''.join('\\x' + format(v, '02x') for v in base64.b64decode(encoded, validate=True))
        lines.append('static const unsigned char ' + name + '[] = "' + literal + '";')
    lines += ['int main(int argc, char **argv) {',
              '_Alignas(16) unsigned char stack[65536] = {0};',
              'uint64_t x[31] = {0}, sp = (uintptr_t)(stack + 32768), address = 0, target = 0;',
              'uint128_t v[32] = {0};',
              'uint64_t A = 0, B = 0, R = 0; int N = 0, Z = 0, C = 0, V = 0;',
              'x[0] = (uint32_t)argc; x[1] = (uintptr_t)argv;',
              'goto L_' + format(ir['entry'], 'x') + ';']
    for instruction in ir['instructions']:
        lines.append('L_' + format(instruction['address'], 'x') + ': ;')
        lines.extend(translated_statements(instruction, addresses, abi))
    lines += ['return 125;', 'indirect_return:', 'switch (target) {']
    lines.extend('case ' + str(a) + ': goto L_' + format(a, 'x') + ';' for a in sorted(addresses))
    lines += ['default: return 125;', '}', '}']
    return '\n'.join(lines) + '\n'


def inspect_binary(original, public_abi=None):
    path = Path(original).resolve()
    before = sha(path)
    ir = recover_ir(path)
    abi = recover_abi(ir['imports'], ir['globals'], public_abi)
    generate_c(ir, abi)  # Fail before presenting untranslatable IR as executable evidence.
    if sha(path) != before:
        raise UnsupportedBinary('ORIGINAL_CHANGED_DURING_RECOVERY')
    target = BinaryTriageReport(str(path), before, path.stat().st_size, ir['architecture'], None)
    spec = {'backend': BACKEND, 'original_path': str(path), 'original_sha256': before,
            'ir': ir, 'abi': abi, 'application_logic_source': 'original machine instructions, not source code or oracle output',
            'scope': 'Selected ARM64 Mach-O text section, integer/pointer ABI, recovered C strings and libc imports. Functional CLI/files/locale corpus; no universal equivalence or GUI claim.',
            'instruction_count': len(ir['instructions']), 'untranslated_instructions': 0}
    bundles = [str(p) for p in path.parents if p.suffix == '.app']
    if bundles or 'ElectronMain' in ir['imports']:
        spec['requires_application_verification'] = True
        spec['application_bundles'] = bundles
    return EvidenceEnvelopeV2(target=target, clean_room_specification=spec)


def linker_arguments(spec):
    arguments = []
    for library in spec.get('link_dependencies', []):
        if sha(library['path']) != library['sha256']:
            raise UnsupportedBinary('LINK_DEPENDENCY_CHANGED')
        arguments.append(library['path'])
        if library.get('rpath'):
            arguments += ['-Wl,-rpath,' + library['rpath']]
    return arguments


def generate_binary(envelope, directory):
    spec = envelope.clean_room_specification
    if spec.get('backend') != BACKEND:
        raise UnsupportedBinary('BINARY_TRANSLATION_EVIDENCE_REQUIRED')
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / 'recovered.c'
    source.write_text(generate_c(spec['ir'], spec['abi']))
    # Match argv[0] diagnostics by retaining the executable basename, not its path.
    binary = directory / Path(spec['original_path']).name
    command = ['clang', '-std=c11', '-O2', '-fno-strict-aliasing', str(source), *linker_arguments(spec), '-o', str(binary)]
    with (directory / 'build.log').open('wb') as log:
        built = subprocess.run(command, stdout=log, stderr=log, timeout=60)
        if built.returncode:
            raise UnsupportedBinary('C_COMPILATION_FAILED: ' + str(directory / 'build.log'))
    spec.update(source_sha256=sha(source), implementation_sha256=sha(binary), build_command=command,
                compiler=command_output(['clang', '--version']).splitlines()[0])
    return [binary, source]


def encode(data):
    return base64.b64encode(data).decode()


def cli_cases(seed):
    """Generic file/stdio CLI corpus; no target-specific expected results."""
    rng = random.Random(seed)
    samples = [b'', b'\n', b'abc', b'abc\n', b'one\ntwo\n', b'a\r\nb\r\n',
               b'a\x00b\n', bytes(range(256)), 'mañana café\n日本語 月\n🙂🧪\n'.encode(),
               ('a' + '\u0301' * 3 + '\n').encode(), b'x' * 65537 + b'\n']
    for _ in range(36):
        alphabet = 'abcdefXYZ0123456789 \t\nñé日月🙂'
        samples.append(''.join(rng.choices(alphabet, k=rng.randrange(1, 2049))).encode())
    cases = []
    for locale in ('C', 'en_US.UTF-8'):
        for data in samples:
            cases.append({'argv': [], 'stdin': encode(data), 'files': {}, 'locale': locale})
        for index in range(12):
            files = {'a.txt': encode(samples[index % len(samples)]), 'dir/b.txt': encode(samples[-index-1])}
            for args in (['a.txt'], ['a.txt', 'dir/b.txt'], ['missing', 'a.txt'], ['a.txt', 'missing'], ['--', 'dir/b.txt'], ['dir']):
                cases.append({'argv': args, 'stdin': encode(b''), 'files': files, 'locale': locale})
        for flag in ['-' + chr(c) for c in range(ord('a'), ord('z') + 1)] + ['--help', '--version', '--unknown', '-']:
            cases.append({'argv': [flag], 'stdin': encode(samples[-1]), 'files': {}, 'locale': locale})
        for args in (['0'], ['1'], ['2'], ['1', '2'], ['3', '7'], ['7', '3'], ['-1'], ['1', '2', '3']):
            for data in samples[:10] + samples[-4:]:
                cases.append({'argv': args, 'stdin': encode(data), 'files': {}, 'locale': locale})
        cases.append({'argv': ['--', '-a'], 'stdin': '', 'files': {'-a': encode(samples[-2])}, 'locale': locale})
        cases.append({'argv': ['mañana 日.txt'], 'stdin': '', 'files': {'mañana 日.txt': encode(samples[-3])}, 'locale': locale})
    return cases


def execute_case(binary, case, sandbox=None):
    with tempfile.TemporaryDirectory(prefix='c5-native-case-') as directory:
        root = Path(directory); working = root / 'files'; working.mkdir()
        for name, encoded in case['files'].items():
            relative = Path(name)
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('UNSAFE_FIXTURE_PATH')
            path = working / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(base64.b64decode(encoded))
        (root / 'stdin').write_bytes(base64.b64decode(case['stdin']))
        # Both processes receive exactly the same argv[0]. This is input
        # equality, not stderr normalization (getopt prints argv[0] verbatim).
        argv = [Path(binary).name, *case['argv']]
        if sandbox:
            command = [str(sandbox[0]), '-p', sandbox[1], '/bin/sh', '-c',
                       'exec -a "$0" "$@"', argv[0], str(binary), *case['argv']]
            executable = None
        else:
            command, executable = argv, str(binary)
        env = {'PATH': os.defpath, 'HOME': str(root), 'TMPDIR': str(root),
               'LANG': case['locale'], 'LC_ALL': case['locale']}
        try:
            with (root / 'stdin').open('rb') as inp, (root / 'stdout').open('wb') as out, (root / 'stderr').open('wb') as err:
                process = subprocess.run(command, executable=executable, stdin=inp, stdout=out, stderr=err, cwd=working, env=env, timeout=5)
            if (root / 'stdout').stat().st_size + (root / 'stderr').stat().st_size > 8 * 1024**2:
                return {'error': 'OUTPUT_LIMIT'}
            files = {str(p.relative_to(working)): sha(p) for p in sorted(working.rglob('*')) if p.is_file()}
            return {'returncode': process.returncode, 'stdout': encode((root / 'stdout').read_bytes()),
                    'stderr': encode((root / 'stderr').read_bytes()), 'files': files}
        except subprocess.TimeoutExpired:
            return {'error': 'TIMEOUT'}


def independence_profile(original):
    if not shutil.which('sandbox-exec'):
        raise UnsupportedBinary('OS_ENFORCED_ORIGINAL_DENIAL_UNAVAILABLE')
    profile = '(version 1)(allow default)(deny file-read* (literal ' + json.dumps(str(original)) + '))(deny process-exec (literal ' + json.dumps(str(original)) + '))'
    # Prove this is enforced, not just a claimed profile. Both attempts must fail.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        blocked_exec = subprocess.run(['sandbox-exec', '-p', profile, str(original)], stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=5).returncode != 0
        blocked_read = subprocess.run(['sandbox-exec', '-p', profile, '/bin/cat', str(original)], stdout=out, stderr=err, timeout=5).returncode != 0
    if not blocked_read or not blocked_exec:
        raise UnsupportedBinary('ORIGINAL_DENIAL_NOT_ENFORCED')
    return ['sandbox-exec', profile], {'original_read_denied': blocked_read, 'original_execution_denied': blocked_exec, 'profile': profile}


def audit_binary(envelope, implementation, seed=None):
    spec = envelope.clean_room_specification
    result = {'status': 'INCOMPLETE', 'verified_cases': 0, 'coverage_percent': 0.,
              'proof_kind': 'Static instruction translation plus fresh bounded differential execution',
              'scope': spec.get('scope')}
    try:
        if spec.get('backend') != BACKEND:
            raise UnsupportedBinary('BINARY_EVIDENCE_REQUIRED')
        original = Path(spec['original_path']).resolve(); binary = Path(implementation).resolve()
        if original == binary or sha(original) != spec['original_sha256'] or envelope.target.sha256 != spec['original_sha256'] or str(original) != envelope.target.target_path:
            raise UnsupportedBinary('ORIGINAL_BINDING_MISMATCH')
        # Re-read the original; edited evidence must not certify invented logic.
        if recover_ir(original) != spec['ir'] or recover_abi(spec['ir']['imports'], spec['ir']['globals'], spec['abi'].get('public_abi')) != spec['abi']:
            raise UnsupportedBinary('IR_OR_ABI_NOT_DERIVED_FROM_ORIGINAL')
        source = binary.parent / 'recovered.c'
        if source.read_text() != generate_c(spec['ir'], spec['abi']) or sha(source) != spec['source_sha256'] or sha(binary) != spec['implementation_sha256']:
            raise UnsupportedBinary('GENERATED_ARTIFACT_CHANGED')
        # Bind machine code to recovered source, rather than trusting a supplied
        # hash of an arbitrary executable. Clang's emitted text must reproduce.
        with tempfile.TemporaryDirectory(prefix='c5-recompile-') as rebuild:
            rebuilt_source = Path(rebuild) / 'recovered.c'; rebuilt_source.write_text(source.read_text())
            rebuilt_binary = Path(rebuild) / binary.name
            command_output(['clang', '-std=c11', '-O2', '-fno-strict-aliasing', str(rebuilt_source), *linker_arguments(spec), '-o', str(rebuilt_binary)])
            expected_text = command_output(['otool', '-s', '__TEXT', '__text', str(rebuilt_binary)]).splitlines()[1:]
            actual_text = command_output(['otool', '-s', '__TEXT', '__text', str(binary)]).splitlines()[1:]
            if expected_text != actual_text:
                raise UnsupportedBinary('EXECUTABLE_TEXT_NOT_COMPILED_FROM_RECOVERED_SOURCE')
        application_required = (any(p.suffix == '.app' for p in original.parents) or
                                'ElectronMain' in spec['ir']['imports'])
        if application_required or spec.get('requires_application_verification'):
            result.update(reason='APPLICATION_UI_AND_API_VERIFICATION_REQUIRED',
                          native_code_recompiled=True, native_instruction_count=len(spec['ir']['instructions']),
                          application_bundles=spec.get('application_bundles', []))
            return result
        imports = set(re.findall(r'^\s*(?:U )?(_[A-Za-z0-9_]+)\s*$', command_output(['nm', '-u', str(binary)]), re.M))
        allowed = {'_' + n for n in spec['ir']['imports'] + spec['ir']['globals']} | {'_memcpy', '_memset', '___stack_chk_fail', '___stack_chk_guard', '___chkstk_darwin', '___bzero', '_bzero'}
        if imports - allowed:
            raise UnsupportedBinary('UNRECOVERED_NATIVE_DEPENDENCY: ' + repr(imports - allowed))
        sandbox, isolation = independence_profile(original)
        seed = secrets.randbits(64) if seed is None else seed
        cases = cli_cases(seed)
        comparisons = []
        for case in cases:
            expected = execute_case(original, case)
            actual = execute_case(binary, case, sandbox)
            comparisons.append({'input': case, 'original': expected, 'reconstructed': actual,
                                'matches': expected == actual and 'error' not in expected and expected['returncode'] >= 0})
        verified = sum(c['matches'] for c in comparisons)
        unchanged = sha(original) == spec['original_sha256'] and sha(binary) == spec['implementation_sha256'] and sha(source) == spec['source_sha256']
        result.update(status='PASS' if verified == len(cases) and unchanged else 'FAIL',
                      reason='ALL_DECLARED_CASES_MATCH' if verified == len(cases) and unchanged else 'LIVE_DIFFERENTIAL_MISMATCH',
                      verified_cases=verified, total_cases=len(cases), coverage_percent=100 * verified / len(cases),
                      verification_seed=seed, instruction_count=len(spec['ir']['instructions']),
                      executable_text_reproduced_from_source=True,
                      untranslated_instructions=0, imports=sorted(imports), isolation=isolation,
                      original_sha256=spec['original_sha256'], implementation_sha256=sha(binary),
                      source_sha256=sha(source), cases=comparisons)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        result.update(status='FAIL', reason=str(error))
    return result


def reconstruct_binary(original, directory, seed=None, public_abi=None, link_dependencies=None):
    root = Path(directory).resolve(); root.mkdir(parents=True, exist_ok=True)
    (root / 'verification.json').write_text(json.dumps({'status': 'INCOMPLETE', 'reason': 'RECOVERY_IN_PROGRESS'}))
    try:
        envelope = inspect_binary(original, public_abi)
        if link_dependencies:
            envelope.clean_room_specification['link_dependencies'] = link_dependencies
        binary, source = generate_binary(envelope, root)
        report = audit_binary(envelope, binary, seed)
        envelope.falsification_verdict = report['status']
        (root / 'evidence.json').write_text(envelope.model_dump_json(indent=2))
        (root / 'verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
        return {k: v for k, v in report.items() if k != 'cases'}
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        result = {'status': 'INCOMPLETE', 'reason': str(error)}
        (root / 'verification.json').write_text(json.dumps(result, indent=2))
        return result
