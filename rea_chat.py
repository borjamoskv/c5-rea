"""Generate a native chat server and falsify it against installed LM Studio."""

import ast
import copy
import concurrent.futures
import ctypes
import json
import os
import random
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from rea_llm import (FUNCTIONS, _ctype, _json_request, _reference_identity,
                     file_hash, inspect_abi, inspect_native, native_program)


BACKEND = 'native-chat-http-sse-v1'


class NativeResourceMonitor:
    """Observe the actual child footprint, including file-backed vs dirty RAM.

    Darwin rusage_info has a stable prefix through ri_phys_footprint (v0..v6).
    The oversize buffer permits the full kernel structure without truncation.
    No process command lines, environment or private server keys are read.
    """
    def __init__(self, pid, path):
        self.pid, self.path = pid, Path(path)
        self.stop_event = threading.Event()
        self.peak_footprint = self.peak_resident = self.samples = 0
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        if sys.platform != 'darwin':
            return
        native = ctypes.CDLL('/usr/lib/libproc.dylib')
        native.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        native.proc_pid_rusage.restype = ctypes.c_int
        started = time.monotonic()
        with self.path.open('w') as log:
            while not self.stop_event.is_set():
                data = ctypes.create_string_buffer(1024)
                if native.proc_pid_rusage(self.pid, 4, data) == 0:
                    resident = ctypes.c_uint64.from_buffer(data, 64).value
                    footprint = ctypes.c_uint64.from_buffer(data, 72).value
                    self.peak_footprint = max(self.peak_footprint, footprint)
                    self.peak_resident = max(self.peak_resident, resident)
                    self.samples += 1
                    log.write(json.dumps({'pid': self.pid, 'seconds': time.monotonic() - started,
                                          'resident_bytes': resident, 'physical_footprint_bytes': footprint}) + '\n')
                    log.flush()
                self.stop_event.wait(0.5)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=2)
        return {'samples': self.samples, 'peak_physical_footprint_bytes': self.peak_footprint,
                'peak_resident_bytes': self.peak_resident}


def parse_sse(raw):
    """Strictly parse data-only SSE, preserving event order and token boundaries."""
    events = []
    for frame in raw.replace('\r\n', '\n').split('\n\n'):
        if not frame.strip():
            continue
        lines = frame.splitlines()
        if len(lines) != 1 or not lines[0].startswith('data: '):
            raise ValueError('INVALID_SSE_FRAMING')
        data = lines[0][6:]
        events.append('[DONE]' if data == '[DONE]' else json.loads(data))
    if not events or events[-1] != '[DONE]' or events.count('[DONE]') != 1:
        raise ValueError('MISSING_OR_DUPLICATE_SSE_DONE')
    return events


def canonical_response(response):
    """Normalize only generated request identity and wall-clock creation time.

    Every other JSON key/value and every stream delta must match exactly.
    IDs and timestamps must be valid and stable inside an individual stream.
    """
    result = copy.deepcopy(response)
    objects = result['events'][:-1] if 'events' in result else [result['json']]
    identities = set()
    for value in objects:
        identifier, created = value['id'], value['created']
        if not isinstance(identifier, str) or not identifier.startswith('chatcmpl-') or len(identifier) < 12:
            raise ValueError('INVALID_COMPLETION_ID')
        if type(created) is not int or created <= 0:
            raise ValueError('INVALID_CREATION_TIME')
        identities.add((identifier, created))
        value['id'], value['created'] = '<REQUEST_ID>', '<UNIX_TIME>'
    if len(identities) != 1:
        raise ValueError('UNSTABLE_STREAM_IDENTITY')
    result.pop('raw', None)
    result.pop('arrival_seconds', None)
    return result


def capture_chat(base, request, record_path=None):
    started = time.monotonic()
    query = urllib.request.Request(base.rstrip('/') + '/v1/chat/completions',
                                   data=json.dumps(request, ensure_ascii=False).encode(),
                                   headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(query, timeout=180) as response:
        result = {'status': response.status, 'content_type': response.headers.get_content_type()}
        if request.get('stream'):
            lines, arrival = [], []
            while True:
                line = response.readline()
                if not line:
                    break
                lines.append(line)
                if line.startswith(b'data: '):
                    arrival.append(time.monotonic() - started)
            raw = b''.join(lines).decode('utf-8')
            if record_path:
                Path(record_path).write_text(raw)
            result.update({'events': parse_sse(raw), 'raw': raw, 'arrival_seconds': arrival})
        else:
            result['json'] = json.load(response)
            if record_path:
                Path(record_path).write_text(json.dumps(result, ensure_ascii=False, indent=2))
    canonical_response(result)  # Reject malformed protocol before comparing it.
    return result


def learn_wire_profile(base, model_id):
    """Observe schemas, then erase all generated text and numerical usage."""
    request = {'model': model_id, 'messages': [
        {'role': 'system', 'content': 'Responde en español.'},
        {'role': 'user', 'content': 'Explica qué es sumar dos números.'}],
        'temperature': 0, 'repeat_penalty': 1.0, 'seed': 42, 'max_tokens': 16}
    completion = capture_chat(base, {**request, 'stream': False})
    stream = capture_chat(base, {**request, 'stream': True, 'stream_options': {'include_usage': True}})
    first = next(e for e in stream['events'][:-1] if e.get('choices') and e['choices'][0]['delta'].get('role'))
    middle = next(e for e in stream['events'][:-1] if e.get('choices') and 'content' in e['choices'][0]['delta'] and 'role' not in e['choices'][0]['delta'])
    finish = next(e for e in stream['events'][:-1] if e.get('choices') and e['choices'][0]['finish_reason'] is not None)
    usage = next(e for e in stream['events'][:-1] if not e.get('choices') and 'usage' in e)
    profile = copy.deepcopy({'completion': completion['json'], 'first': first, 'middle': middle, 'finish': finish, 'usage': usage})
    for value in profile.values():
        value['id'], value['created'] = '', 0
        if 'usage' in value:
            value['usage'] = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0,
                              'completion_tokens_details': {'reasoning_tokens': 0}}
        for choice in value.get('choices', []):
            if 'message' in choice:
                choice['message']['content'] = ''
            if 'content' in choice.get('delta', {}):
                choice['delta']['content'] = ''
    return profile, {'request': request, 'completion': completion, 'stream': stream}


def chat_program(specification):
    """Compose ABI-derived initialization with the generic native HTTP runtime."""
    raw = native_program(specification) if not specification.get('native_worker_path') else ast.Module(body=[], type_ignores=[])
    prefix = []
    for node in raw.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'requests' for t in node.targets):
            break
        prefix.append(node)
    signature = specification['abi']['functions']['llama_model_chat_template']
    if not specification.get('native_worker_path'):
        prefix.extend(ast.parse('lib.llama_model_chat_template.restype = ' + _ctype(signature['return']) + '\n'
                            'lib.llama_model_chat_template.argtypes = [' + ', '.join(_ctype(item) for item in signature['arguments']) + ']').body)
    emitted = {
        'renderer_path': specification['renderer_path'], 'reference_model': specification['reference_model'],
        'wire_profile': specification['wire_profile'],
    }
    if specification.get('native_worker_path'):
        emitted.update(native_worker_path=specification['native_worker_path'], worker_config={
            'runtime_directory': str(Path(specification['library_path']).parent),
            'model_path': specification['model_path'], 'context_length': specification['context_length'],
            'gpu_layers': specification['gpu_layers'],
        })
    prefix.append(ast.Assign([ast.Name('CHAT_SPEC', ast.Store())], ast.parse(repr(emitted), mode='eval').body))
    runtime = ast.parse(Path(__file__).with_name('rea_chat_runtime.py').read_text())
    prefix.extend(node for node in runtime.body if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Constant))
    prefix.append(ast.Expr(ast.Call(ast.Name('serve_chat', ast.Load()), [], [])))
    return ast.fix_missing_locations(ast.Module(body=prefix, type_ignores=[]))


def build_native_worker(specification, headers, root):
    root, headers = Path(root).resolve(), Path(headers).resolve()
    source = Path(__file__).with_name('rea_chat_worker.cpp')
    if not (headers / 'json.hpp').is_file():
        raise ValueError('Native worker requires pinned nlohmann json.hpp in the supplied headers directory')
    directory = root / 'native'
    directory.mkdir(parents=True, exist_ok=True)
    copied = directory / source.name
    shutil.copy2(source, copied)
    output = directory / 'c5_chat_worker'
    runtime = Path(specification['library_path']).parent
    command = ['clang++', '-std=c++17', '-O2', '-I', str(headers), str(copied),
               '-L', str(runtime), '-lllama', '-lggml', '-lc5_jinja',
               '-Wl,-rpath,' + str(runtime), '-o', str(output)]
    with (directory / 'build.log').open('wb') as log:
        try:
            subprocess.run(command, stdout=log, stderr=log, check=True, timeout=120)
            subprocess.run(['codesign', '--force', '--sign', '-', str(output)], stdout=log, stderr=log, check=True, timeout=30)
        except subprocess.CalledProcessError as error:
            raise ValueError('Native worker build failed; see ' + str(directory / 'build.log')) from error
    specification['native_worker_path'] = str(output)
    specification['native_dependencies'][str(output)] = file_hash(output)
    specification['native_worker_build'] = {'command': command, 'source_sha256': file_hash(copied),
                                            'json_header_sha256': file_hash(headers / 'json.hpp')}
    return output


def generate_chat(envelope, output_directory):
    specification = envelope.clean_room_specification
    if specification.get('backend') != BACKEND:
        raise ValueError('Native chat evidence required')
    root = Path(output_directory)
    root.mkdir(parents=True, exist_ok=True)
    target = root / 'chat_server.py'
    target.write_text('#!/usr/bin/env python3\n' + ast.unparse(chat_program(specification)) + '\n')
    target.chmod(0o755)
    specification['implementation_sha256'] = file_hash(target)
    return [target]


def chat_cases(model_id, seed):
    rng = random.Random(seed)
    nonce = ''.join(rng.choices('abcdef0123456789', k=18))
    scenarios = [
        ([{'role': 'user', 'content': 'Reply with exactly one word: hola'}], 16, {}),
        ([{'role': 'system', 'content': 'Responde siempre en español.'}, {'role': 'user', 'content': 'How much is 2+2?'}], 16, {}),
        ([{'role': 'user', 'content': 'Remember this identifier: ' + nonce},
          {'role': 'assistant', 'content': 'I will remember it.'},
          {'role': 'user', 'content': 'Return only that identifier.'}], 32, {}),
        ([{'role': 'user', 'content': '日本語で月曜日の次の日だけ答えてください。'}], 16, {}),
        ([{'role': 'user', 'content': 'Write a Python function to add two integers.'}], 8, {}),
        ([{'role': 'user', 'content': 'List the numbers from 1 to 10 separated by commas.'}], 32, {'stop': ['3']}),
        ([{'role': 'user', 'content': 'Di únicamente: mañana, café y pingüino.'}], 16, {}),
        ([{'role': 'user', 'content': 'Explain the water cycle.'}], 1, {}),
    ]
    requests = []
    for index, (messages, limit, options) in enumerate(scenarios):
        for stream in (False, True):
            request = {'model': model_id, 'messages': messages, 'max_tokens': limit,
                       'temperature': 0, 'repeat_penalty': 1.0, 'seed': 42, 'stream': stream, **options}
            if stream and index != 4:
                request['stream_options'] = {'include_usage': True}
            requests.append(request)
    requests.extend(copy.deepcopy(requests[:2]))
    return requests


def advanced_chat_cases(model_id, seed):
    requests = chat_cases(model_id, seed)
    for temperature in (.2, .7, 1.1):
        for stream in (False, True):
            request = {'model': model_id, 'messages': [{'role': 'user', 'content': 'Suggest one unusual name for a tiny robot.'}],
                       'temperature': temperature, 'seed': 123456, 'top_k': 40, 'top_p': .95, 'min_p': .05,
                       'repeat_penalty': 1., 'max_tokens': 24, 'stream': stream}
            if stream: request['stream_options'] = {'include_usage': True}
            requests.append(request)
    tool = {'type': 'function', 'function': {'name': 'read_file', 'description': 'Read a file from disk and return its contents.',
            'parameters': {'type': 'object', 'properties': {'path': {'type': 'string'}}, 'required': ['path']}}}
    for stream in (False, True):
        request = {'model': model_id, 'messages': [{'role': 'user', 'content': 'Please read /tmp/c5-proof.txt.'}],
                   'tools': [tool], 'tool_choice': 'auto', 'temperature': 0, 'repeat_penalty': 1., 'seed': 42,
                   'max_tokens': 128, 'stream': stream}
        if stream: request['stream_options'] = {'include_usage': True}
        requests.append(request)
    # Fresh independent prompts, same parameters as the stochastic serial cases.
    # Groups of two and four must be admitted simultaneously by the HTTP layer.
    for count in (2, 4):
        for i in range(count):
            requests.append({'model': model_id, 'messages': [{'role': 'user', 'content':
                'Write a short sentence about ' + ('the moon', 'a forest', 'the sea', 'a robot')[i] + '.'}],
                'temperature': .7, 'seed': 901 + i, 'top_k': 40, 'top_p': .95, 'min_p': .05,
                'repeat_penalty': 1., 'max_tokens': 24, 'stream': True, 'stream_options': {'include_usage': True}})
    return requests


def execute_tool_roundtrip(base, request, response, fixture, directory):
    """Execute only the actual model-issued read_file call on the audit fixture."""
    proof = {'verified': False, 'reason': 'NO_STRUCTURED_TOOL_CALL'}
    calls = response.get('json', {}).get('choices', [{}])[0].get('message', {}).get('tool_calls', [])
    if len(calls) != 1:
        return proof
    call = calls[0]
    function = call.get('function', {})
    arguments = json.loads(function.get('arguments', '{}'))
    if call.get('type') != 'function' or function.get('name') != 'read_file' or arguments != {'path': str(fixture)} or not call.get('id'):
        return {**proof, 'reason': 'UNEXPECTED_TOOL_CALL'}
    content = fixture.read_text()
    history = copy.deepcopy(request['messages']) + [response['json']['choices'][0]['message'],
              {'role': 'tool', 'tool_call_id': call['id'], 'content': content}]
    responses = []
    for stream in (False, True):
        followup = {**request, 'messages': history, 'stream': stream, 'max_tokens': 128}
        if stream: followup['stream_options'] = {'include_usage': True}
        responses.append(capture_chat(base, followup, directory / ('tool_roundtrip_' + str(stream) + '.txt')))
    return {'verified': True, 'reason': 'REAL_FILE_READ_AND_RESULT_SUBMITTED', 'tool_name': function['name'],
            'file_sha256': file_hash(fixture), 'result': content, 'responses': responses}


def capture_plan(base, requests, root, advanced=False):
    responses = []
    timings = []
    serial = len(requests) - 6 if advanced else len(requests)
    def one(index, barrier=None):
        if barrier: barrier.wait(timeout=15)
        start = time.monotonic()
        response = capture_chat(base, requests[index], root / ('response_' + str(index) + '.txt'))
        return response, {'index': index, 'start': start, 'end': time.monotonic()}
    for index in range(serial):
        response, timing = one(index)
        responses.append(response); timings.append(timing)
        (root / 'checkpoint.json').write_text(json.dumps({'requests': requests, 'responses': responses}, ensure_ascii=False, indent=2))
    if advanced:
        for first, count in ((serial, 2), (serial+2, 4)):
            barrier = threading.Barrier(count)
            with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
                futures = [pool.submit(one, i, barrier) for i in range(first, first+count)]
                for future in futures:
                    response, timing = future.result()
                    responses.append(response); timings.append(timing)
    (root / 'timings.json').write_text(json.dumps(timings, indent=2))
    return responses


def audit_chat(envelope, implementation, manage_reference=False, output_directory=None, seed=None):
    spec = envelope.clean_room_specification
    result = {'status': 'INCOMPLETE', 'verified_cases': 0, 'coverage_percent': 0.0,
              'scope': spec.get('scope'), 'normalization': 'Only id and created; their format and within-stream stability are checked. Every remaining field and delta must match.'}
    if spec.get('backend') != BACKEND or not manage_reference:
        return {**result, 'reason': 'EXPLICIT_CHAT_REFERENCE_VERIFICATION_REQUIRED'}
    root = Path(output_directory or Path(implementation).parent / 'chat_verification').resolve()
    root.mkdir(parents=True, exist_ok=True)
    candidate, base = Path(implementation).resolve(), spec['reference_url']
    loaded_by_audit = initially_loaded = reference_unloaded = stopped = False
    candidate_process = None
    monitor = None
    worker_monitor = None
    lifecycle = []

    def finish(status, reason, **details):
        result.update(status=status, reason=reason, **details)
        return result

    def cli(*arguments):
        with tempfile.TemporaryFile() as log:
            process = subprocess.run([spec['lms_path'], *arguments], stdout=log, stderr=log, timeout=90)
        lifecycle.append({'command': list(arguments), 'returncode': process.returncode})
        if process.returncode:
            raise ValueError('REFERENCE_LIFECYCLE_FAILED')

    try:
        if not candidate.is_file() or file_hash(candidate) != spec.get('implementation_sha256') or ast.dump(ast.parse(candidate.read_text())) != ast.dump(chat_program(spec)):
            return finish('FAIL', 'GENERATED_CHAT_IMPLEMENTATION_CHANGED_OR_MISSING')
        if file_hash(spec['model_path']) != spec['weights_sha256'] or any(file_hash(path) != h for path, h in spec['native_dependencies'].items()):
            return finish('FAIL', 'NATIVE_DEPENDENCY_CHANGED')
        target = next(m for m in _json_request(base, '/api/v1/models')['models'] if m['key'] == spec['reference_model'])
        initially_loaded = bool(target['loaded_instances'])
        if initially_loaded and target['loaded_instances'][0]['config']['context_length'] != spec['context_length']:
            return finish('INCOMPLETE', 'REFERENCE_CONTEXT_DOES_NOT_MATCH')
        if not initially_loaded:
            _json_request(base, '/api/v1/models/load', {'model': spec['reference_model'], 'context_length': spec['context_length'], 'eval_batch_size': 2048, 'flash_attention': True})
            loaded_by_audit = True
        result['reference_identity'] = _reference_identity(spec)
        seed = secrets.randbits(64) if seed is None else seed
        advanced = spec.get('verification_suite') == 'advanced-v1'
        requests = advanced_chat_cases(spec['reference_model'], seed) if advanced else chat_cases(spec['reference_model'], seed)
        fixture = root / 'tool_fixture.txt'
        if advanced:
            fixture.write_text('C5-REA actual file: ' + secrets.token_hex(24))
            for request in requests:
                if request.get('tools'):
                    request['messages'][0]['content'] = 'Please read ' + str(fixture) + '.'
        original_dir = root / 'original_capture'; original_dir.mkdir(exist_ok=True)
        originals = capture_plan(base, requests, original_dir, advanced)
        original_tool = execute_tool_roundtrip(base, requests[24], originals[24], fixture, original_dir) if advanced else None
        if advanced: (original_dir / 'tool_proof.json').write_text(json.dumps(original_tool, ensure_ascii=False, indent=2))
        (root / 'original.json').write_text(json.dumps({'requests': requests, 'responses': originals}, ensure_ascii=False, indent=2))
        if canonical_response(originals[0]) != canonical_response(originals[16]) or canonical_response(originals[1]) != canonical_response(originals[17]):
            return finish('INCOMPLETE', 'REFERENCE_NOT_DETERMINISTIC')
        cli('unload', spec['reference_model'])
        reference_unloaded = True
        deadline = time.monotonic() + 60
        while subprocess.run(['ps', '-p', str(result['reference_identity']['engine_pid']), '-o', 'pid='], capture_output=True, timeout=10).returncode == 0:
            if time.monotonic() >= deadline:
                return finish('INCOMPLETE', 'REFERENCE_PROCESS_DID_NOT_EXIT')
            time.sleep(0.5)
        cli('server', 'stop')
        stopped = True
        try:
            _json_request(base, '/v1/models', timeout=2)
        except OSError:
            result['reference_offline_during_candidate'] = True
        else:
            return finish('FAIL', 'REFERENCE_STILL_REACHABLE')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        candidate_base = 'http://127.0.0.1:' + str(port)
        with (root / 'native.log').open('wb') as log, (root / 'server.log').open('wb') as output:
            candidate_process = subprocess.Popen([sys.executable, '-I', '-S', '-X', 'faulthandler', str(candidate), '--port', str(port)], stdin=subprocess.DEVNULL, stdout=output, stderr=log, start_new_session=True)
            result['candidate_pid'] = candidate_process.pid
            monitor = NativeResourceMonitor(candidate_process.pid, root / 'resources.jsonl')
            monitor.start()
            deadline = time.monotonic() + 180
            while True:
                if candidate_process.poll() is not None:
                    return finish('FAIL', 'NATIVE_CHAT_PROCESS_FAILED', returncode=candidate_process.returncode)
                try:
                    health = _json_request(candidate_base, '/health', timeout=1)
                    if health['ready']:
                        break
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    return finish('FAIL', 'NATIVE_CHAT_STARTUP_TIMEOUT')
                time.sleep(0.2)
            if spec.get('native_worker_path'):
                worker_monitor = NativeResourceMonitor(health['native_pid'], root / 'native_resources.jsonl')
                worker_monitor.start()
            actual_dir = root / 'candidate_capture'; actual_dir.mkdir(exist_ok=True)
            actuals = capture_plan(candidate_base, requests, actual_dir, advanced)
            candidate_tool = execute_tool_roundtrip(candidate_base, requests[24], actuals[24], fixture, actual_dir) if advanced else None
            if advanced: (actual_dir / 'tool_proof.json').write_text(json.dumps(candidate_tool, ensure_ascii=False, indent=2))
            if candidate_process.poll() is not None:
                return finish('FAIL', 'NATIVE_CHAT_EXITED_BEFORE_SHUTDOWN', returncode=candidate_process.returncode)
            candidate_process.terminate()
            candidate_process.wait(timeout=15)
            result['candidate_shutdown_exitcode'] = candidate_process.returncode
            if candidate_process.returncode != 0:
                return finish('FAIL', 'NATIVE_CHAT_SHUTDOWN_FAILED', returncode=candidate_process.returncode)
            candidate_process = None
        (root / 'candidate.json').write_text(json.dumps({'health': health, 'requests': requests, 'responses': actuals}, ensure_ascii=False, indent=2))
        logs = [json.loads(line) for line in (root / 'native.log').read_text(errors='replace').splitlines() if line.startswith('{') and '"event"' in line]
        completed = [item for item in logs if item['event'] == 'native_complete']
        worker_shutdown = not spec.get('native_worker_path') or any(item['event'] == 'native_worker_closed' and item['exitcode'] == 0 for item in logs)
        streamed_live = []
        for item in completed:
            flushed = [e for e in logs if e['event'] == 'sse_flushed' and e['id'] == item['id'] and e['has_content']]
            if flushed:
                streamed_live.append(flushed[0]['native_decode_calls'] < item['native_decode_calls'])
        comparisons = []
        for request, original, actual in zip(requests, originals, actuals):
            expected, measured = canonical_response(original), canonical_response(actual)
            comparisons.append({'request': request, 'matches': expected == measured, 'expected': expected, 'actual': measured})
        verified = sum(c['matches'] for c in comparisons)
        unchanged = file_hash(candidate) == spec['implementation_sha256'] and file_hash(spec['model_path']) == spec['weights_sha256'] and all(file_hash(path) == h for path, h in spec['native_dependencies'].items())
        native_valid = (worker_shutdown and health['model_parameters'] > 0 and len(completed) == len(requests) + (2 if advanced and candidate_tool['verified'] else 0)
                        and all(e['native_decode_calls'] > 0 for e in completed)
                        and len(streamed_live) == sum(bool(r['stream']) for r in requests) + (1 if advanced and candidate_tool['verified'] else 0) and all(streamed_live))
        advanced_valid = True
        if advanced:
            tool_valid = original_tool['verified'] and candidate_tool['verified'] and original_tool['file_sha256'] == candidate_tool['file_sha256'] and original_tool['result'] == candidate_tool['result'] and all(canonical_response(a) == canonical_response(b) for a, b in zip(original_tool.get('responses', []), candidate_tool.get('responses', [])))
            steps = [e for e in logs if e['event'] == 'native_step' and e['action'] == 'step']
            overlap = any(e['active_sessions'] >= 2 for e in steps) and any(e['active_sessions'] >= 4 for e in steps)
            result.update(tool_calls_executed_and_verified=bool(tool_valid), reference_structured_tool_calls=bool(original_tool['verified']), concurrent_native_sessions=overlap, tool_proof={'original': original_tool, 'candidate': candidate_tool})
            # A text representation is never a verified tool execution. Round-trip
            # verification must explicitly provide this proof before PASS.
            advanced_valid = overlap and result['tool_calls_executed_and_verified']
        result.update({'status': 'PASS'  if verified == len(requests) and unchanged and native_valid and advanced_valid else 'FAIL',
                       'reason': 'ALL_LIVE_CHAT_AND_SSE_CASES_MATCH' if verified == len(requests) and unchanged and native_valid and advanced_valid else 'CHAT_PROTOCOL_OR_INFERENCE_MISMATCH',
                       'verified_cases': verified, 'total_cases': len(requests), 'coverage_percent': round(100 * verified / len(requests), 2),
                       'verification_seed': seed, 'real_native_inference': native_valid, 'streaming_before_generation_finished': streamed_live,
                       'native_model_parameters': health['model_parameters'], 'template_sha256': health['template_sha256'],
                       'implementation_sha256': file_hash(candidate), 'cases': comparisons})
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.TimeoutExpired) as error:
        finish('FAIL' if result.get('reference_offline_during_candidate') else 'INCOMPLETE', type(error).__name__, detail=str(error))
    finally:
        if monitor is not None:
            result['candidate_resources'] = monitor.close()
        if worker_monitor is not None:
            result['native_worker_resources'] = worker_monitor.close()
        if candidate_process is not None:
            result['candidate_exitcode_before_cleanup'] = candidate_process.poll()
            # The entire group belongs to this audit. On failure release its
            # native model before restoring the original, even if HTTP died.
            try:
                os.killpg(candidate_process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        if candidate_process is not None and candidate_process.poll() is None:
            candidate_process.terminate()
            try:
                candidate_process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                candidate_process.kill()
                candidate_process.wait(timeout=10)
        try:
            if stopped:
                cli('server', 'start')
            if initially_loaded and reference_unloaded:
                _json_request(base, '/api/v1/models/load', {'model': spec['reference_model'], 'context_length': spec['context_length']})
            elif loaded_by_audit and not reference_unloaded:
                cli('unload', spec['reference_model'])
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            finish('INCOMPLETE', 'RESTORE_FAILED', detail=str(error))
        result['lifecycle'] = lifecycle
        (root / 'verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
    return result


def reconstruct_chat(model_path, library_path, renderer_path, headers, reference_url, model_id,
                     output_directory, manage_reference=False, context_length=1024, advanced=False):
    root = Path(output_directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    (root / 'verification.json').write_text(json.dumps({'status': 'INCOMPLETE', 'reason': 'DISCOVERY_REQUIRED'}))
    if not manage_reference:
        return {'status': 'INCOMPLETE', 'reason': 'EXPLICIT_CHAT_REFERENCE_VERIFICATION_REQUIRED'}
    envelope = inspect_native(model_path, library_path, headers, reference_url, model_id, context_length)
    spec = envelope.clean_room_specification
    spec['backend'] = BACKEND
    use_worker = Path(model_path).stat().st_size >= 2 * 1024 ** 3
    spec['gpu_layers'] = 999
    spec['cpu_only'] = False
    if use_worker:
        spec['memory_policy'] = 'mmap-no-repack'
    spec['abi'] = inspect_abi(headers, functions=FUNCTIONS + ('llama_model_chat_template',))
    spec['renderer_path'] = str(Path(renderer_path).resolve())
    spec['native_dependencies'][spec['renderer_path']] = file_hash(spec['renderer_path'])
    if use_worker:
        build_native_worker(spec, headers, root)
    if advanced:
        if not use_worker:
            raise ValueError('Advanced sampling/concurrency requires the isolated native worker')
        spec['verification_suite'] = 'advanced-v1'
    spec['scope'] = 'POST /v1/chat/completions; text system/user/assistant histories; greedy temperature=0; JSON and token-level SSE; stop strings; max_tokens 1..64; optional stream usage; normalized request IDs/timestamps only'
    if advanced:
        spec['scope'] += '; advanced suite: seeded temperatures .2/.7/1.1; function calls and actual file result roundtrip; two/four simultaneous native sessions. PASS requires every gate.'
    target = next(m for m in _json_request(reference_url, '/api/v1/models')['models'] if m['key'] == model_id)
    was_loaded = bool(target['loaded_instances'])
    try:
        if not was_loaded:
            _json_request(reference_url, '/api/v1/models/load', {'model': model_id, 'context_length': context_length, 'eval_batch_size': 2048, 'flash_attention': True})
        _reference_identity(spec)
        spec['wire_profile'], discovery = learn_wire_profile(reference_url, model_id)
        (root / 'discovery.json').write_text(json.dumps(discovery, ensure_ascii=False, indent=2))
    finally:
        if not was_loaded:
            with tempfile.TemporaryFile() as log:
                subprocess.run([spec['lms_path'], 'unload', model_id], stdout=log, stderr=log, timeout=90, check=True)
    artifact = generate_chat(envelope, root)[0]
    (root / 'evidence.json').write_text(envelope.model_dump_json(indent=2))
    report = audit_chat(envelope, artifact, manage_reference=True, output_directory=root / 'comparison')
    envelope.falsification_verdict = report['status']
    (root / 'evidence.json').write_text(envelope.model_dump_json(indent=2))
    (root / 'verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
    return {key: value for key, value in report.items() if key != 'cases'}
