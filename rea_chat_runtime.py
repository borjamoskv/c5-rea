"""Generic HTTP/SSE runtime emitted into a self-contained native application.

Response shapes come from observed protocol evidence; all content and token usage
come from the native forward pass. This module never contacts the reference.
"""

import contextlib
import math
import codecs
import copy
import ctypes as ct
import hashlib
import json
import secrets
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer


class NativeChatEngine:
    def __init__(self):
        self.lock = threading.Lock()
        self.renderer = ct.CDLL(CHAT_SPEC['renderer_path'])
        self.renderer.c5_render.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_uint64]
        self.renderer.c5_render.restype = ct.c_int64
        template = lib.llama_model_chat_template(model, None)
        if not template:
            raise ValueError('NO_MODEL_CHAT_TEMPLATE')
        self.template = ct.string_at(template)
        self.template_hash = hashlib.sha256(self.template).hexdigest()

    def prompt(self, messages):
        variables = json.dumps({'messages': messages, 'add_generation_prompt': True,
                                'tools': None, 'bos_token': '', 'eos_token': ''}, ensure_ascii=False).encode()
        capacity = max(4096, len(variables) * 4)
        while True:
            buffer = ct.create_string_buffer(capacity)
            size = self.renderer.c5_render(self.template, variables, buffer, capacity)
            if size < 0:
                raise ValueError('CHAT_TEMPLATE_FAILED: ' + buffer.value.decode(errors='replace'))
            if size < capacity:
                return buffer.raw[:size]
            capacity = size + 1
            if capacity > 1048576:
                raise ValueError('CHAT_TEMPLATE_TOO_LARGE')

    def validate(self, request):
        supported = {'model', 'messages', 'temperature', 'max_tokens', 'stream',
                     'stream_options', 'repeat_penalty', 'seed', 'stop'}
        if set(request) - supported:
            raise ValueError('UNSUPPORTED_PARAMETERS')
        if request.get('model') != CHAT_SPEC['reference_model']:
            raise ValueError('MODEL_NOT_LOADED')
        if request.get('temperature') != 0 or request.get('repeat_penalty') != 1:
            raise ValueError('ONLY_GREEDY_WITHOUT_REPETITION_PENALTY_IS_SUPPORTED')
        limit = request.get('max_tokens')
        if type(limit) is not int or not 1 <= limit <= 64:
            raise ValueError('MAX_TOKENS_OUT_OF_SCOPE')
        messages = request.get('messages')
        if not isinstance(messages, list) or not messages:
            raise ValueError('MESSAGES_REQUIRED')
        for message in messages:
            if set(message) != {'role', 'content'} or message['role'] not in ('system', 'user', 'assistant') or not isinstance(message['content'], str):
                raise ValueError('ONLY_TEXT_MESSAGES_WITH_STANDARD_ROLES_ARE_SUPPORTED')
        if not isinstance(request.get('stream', False), bool):
            raise ValueError('STREAM_MUST_BE_BOOLEAN')
        stops = request.get('stop', [])
        if isinstance(stops, str):
            stops = [stops]
        if not isinstance(stops, list) or any(not isinstance(s, str) or not s for s in stops):
            raise ValueError('INVALID_STOP_STRINGS')
        options = request.get('stream_options', {})
        if not isinstance(options, dict) or set(options) - {'include_usage'}:
            raise ValueError('UNSUPPORTED_STREAM_OPTIONS')
        raw = self.prompt(messages)
        capacity = max(32, len(raw) + 8)
        tokens = (ct.c_int32 * capacity)()
        count = lib.llama_tokenize(vocab, raw, len(raw), tokens, capacity, True, True)
        if count <= 0 or count + limit > cp.n_ctx:
            raise ValueError('CONTEXT_LIMIT_EXCEEDED')
        return tokens, count, limit, stops

    def infer(self, prepared, request_id):
        tokens, count, limit, stops = prepared
        lib.llama_memory_clear(lib.llama_get_memory(ctx), True)
        if lib.llama_decode(ctx, lib.llama_batch_get_one(tokens, count)) != 0:
            raise RuntimeError('PREFILL_FAILED')
        decoder = codecs.getincrementaldecoder('utf-8')('replace')
        sampled, calls, pending = 0, 1, ''
        finish = 'length'
        for step in range(limit):
            token = lib.llama_sampler_sample(sampler, ctx, -1)
            sampled += 1
            if lib.llama_vocab_is_eog(vocab, token):
                finish = 'stop'
                break
            piece = ct.create_string_buffer(16384)
            size = lib.llama_token_to_piece(vocab, token, piece, len(piece), 0, True)
            if not 0 <= size <= len(piece):
                raise RuntimeError('TOKEN_PIECE_TOO_LARGE')
            pending += decoder.decode(piece.raw[:size])
            found = [pending.find(stop) for stop in stops if stop in pending]
            if found:
                visible = pending[:min(found)]
                if visible:
                    yield {'delta': visible, 'native_calls': calls}
                pending = ''
                finish = 'stop'
                break
            hold = max([0] + [length for stop in stops for length in range(1, min(len(stop), len(pending)) + 1) if pending.endswith(stop[:length])])
            visible = pending[:-hold] if hold else pending
            pending = pending[-hold:] if hold else ''
            if visible:
                yield {'delta': visible, 'native_calls': calls}
            current = (ct.c_int32 * 1)(token)
            if lib.llama_decode(ctx, lib.llama_batch_get_one(current, 1)) != 0:
                raise RuntimeError('DECODE_FAILED')
            calls += 1
        tail = pending + decoder.decode(b'', final=True)
        if tail:
            yield {'delta': tail, 'native_calls': calls}
        usage = {'prompt_tokens': count, 'completion_tokens': sampled, 'total_tokens': count + sampled,
                 'completion_tokens_details': {'reasoning_tokens': 0}}
        print(json.dumps({'event': 'native_complete', 'id': request_id, 'native_decode_calls': calls,
                          'sampled_tokens': sampled, 'model_parameters': parameter_count}), file=sys.stderr, flush=True)
        yield {'finish_reason': finish, 'usage': usage, 'native_calls': calls}


class NativeWorkerEngine:
    """Keep model memory in a genuine native executable, outside HTTP Python."""
    def __init__(self):
        self.lock = contextlib.nullcontext()
        self.rpc_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(4)
        self.worker = subprocess.Popen([CHAT_SPEC['native_worker_path']], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=sys.stderr, text=True, bufsize=1)
        print(json.dumps({'event': 'native_worker_started', 'pid': self.worker.pid}), file=sys.stderr, flush=True)
        self.worker.stdin.write(json.dumps(CHAT_SPEC['worker_config']) + '\n')
        self.worker.stdin.flush()
        self.metadata = self.read()
        if not self.metadata.get('ready') or self.metadata['model_parameters'] <= 0:
            raise RuntimeError('NATIVE_WORKER_NOT_READY')
        self.template_hash = hashlib.sha256(self.metadata['template'].encode()).hexdigest()

    def read(self):
        line = self.worker.stdout.readline()
        if not line:
            raise RuntimeError('NATIVE_WORKER_EXITED: ' + str(self.worker.poll()))
        value = json.loads(line)
        if 'error' in value:
            raise ValueError(value['error'])
        return value

    def command(self, value):
        with self.rpc_lock:
            self.worker.stdin.write(json.dumps(value, ensure_ascii=False) + '\n')
            self.worker.stdin.flush()
            return self.read()

    def validate(self, request):
        supported = {'model', 'messages', 'temperature', 'max_tokens', 'stream', 'stream_options', 'repeat_penalty', 'seed', 'stop', 'top_k', 'top_p', 'min_p', 'tools', 'tool_choice'}
        if set(request) - supported or request.get('model') != CHAT_SPEC['reference_model']:
            raise ValueError('UNSUPPORTED_PARAMETERS_OR_MODEL')
        temperature = request.get('temperature')
        if type(temperature) not in (int, float) or not math.isfinite(temperature) or not 0 <= temperature <= 2 or request.get('repeat_penalty') != 1:
            raise ValueError('UNSUPPORTED_SAMPLING')
        if type(request.get('seed')) is not int or not 0 <= request['seed'] < 2**32:
            raise ValueError('EXPLICIT_UINT32_SEED_REQUIRED')
        for key, default in (('top_p', .95), ('min_p', .05)):
            value = request.get(key, default)
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError('INVALID_SAMPLING_PROBABILITY')
        if type(request.get('top_k', 40)) is not int or not 1 <= request.get('top_k', 40) <= 1000:
            raise ValueError('INVALID_TOP_K')
        if type(request.get('max_tokens')) is not int or not 1 <= request['max_tokens'] <= 256:
            raise ValueError('MAX_TOKENS_OUT_OF_SCOPE')
        messages = request.get('messages')
        if not isinstance(messages, list) or not messages:
            raise ValueError('MESSAGES_REQUIRED')
        if any(not isinstance(m, dict) or set(m) - {'role', 'content', 'tool_calls', 'tool_call_id', 'name'} or m.get('role') not in ('system', 'user', 'assistant', 'tool') or not isinstance(m.get('content', ''), (str, type(None))) for m in messages):
            raise ValueError('ONLY_TEXT_MESSAGES_WITH_STANDARD_ROLES_ARE_SUPPORTED')
        stops = request.get('stop', [])
        if isinstance(stops, str):
            stops = [stops]
        if not isinstance(stops, list) or any(not isinstance(s, str) or not s for s in stops):
            raise ValueError('INVALID_STOP_STRINGS')
        options = request.get('stream_options', {})
        if not isinstance(request.get('stream', False), bool) or not isinstance(options, dict) or set(options) - {'include_usage'}:
            raise ValueError('UNSUPPORTED_STREAM_OPTIONS')
        if request.get('tool_choice', 'auto') != 'auto':
            raise ValueError('ONLY_AUTO_TOOL_CHOICE_SUPPORTED')
        if 'tools' in request:
            if not isinstance(request['tools'], list) or any(t.get('type') != 'function' or not isinstance(t.get('function', {}).get('name'), str) or not isinstance(t['function'].get('parameters'), dict) for t in request['tools']):
                raise ValueError('INVALID_FUNCTION_TOOLS')
        session = secrets.token_hex(16)
        self.slots.acquire()
        try:
            self.command({'action': 'prepare', 'session': session, 'request': request})
        except Exception:
            self.command({'action': 'release', 'session': session})
            self.slots.release()
            raise
        return session, stops

    def infer(self, prepared, request_id):
        session, stops = prepared
        try:
            yield from self.infer_session(session, stops, request_id)
        finally:
            self.command({'action': 'release', 'session': session})
            self.slots.release()

    def infer_session(self, session, stops, request_id):
        decoder = codecs.getincrementaldecoder('utf-8')('replace')
        pending = ''
        while True:
            item = self.command({'action': 'step', 'session': session})
            if 'finish_reason' in item:
                final = item
                break
            pending += decoder.decode(bytes.fromhex(item['piece_hex']))
            found = [pending.find(stop) for stop in stops if stop in pending]
            if found:
                visible = pending[:min(found)]
                if visible:
                    yield {'delta': visible, 'native_calls': item['native_calls']}
                pending = ''
                final = self.command({'action': 'stop', 'session': session})
                break
            hold = max([0] + [n for stop in stops for n in range(1, min(len(stop), len(pending)) + 1) if pending.endswith(stop[:n])])
            visible = pending[:-hold] if hold else pending
            pending = pending[-hold:] if hold else ''
            if visible:
                yield {'delta': visible, 'native_calls': item['native_calls']}
        tail = pending + decoder.decode(b'', final=True)
        if tail:
            yield {'delta': tail, 'native_calls': final['native_calls']}
        print(json.dumps({'event': 'native_complete', 'id': request_id, 'native_decode_calls': final['native_calls'],
                          'sampled_tokens': final['usage']['completion_tokens'], 'model_parameters': parameter_count}), file=sys.stderr, flush=True)
        yield final

    def close(self):
        response = self.command({'action': 'shutdown'})
        self.worker.stdin.close()
        self.worker.stdout.close()
        code = self.worker.wait(timeout=15)
        print(json.dumps({'event': 'native_worker_closed', 'pid': self.worker.pid, 'exitcode': code}), file=sys.stderr, flush=True)
        if not response.get('closed') or code != 0:
            raise RuntimeError('NATIVE_WORKER_SHUTDOWN_FAILED')


class ChatHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        return

    def send_json(self, value, status=200):
        payload = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()

    def do_GET(self):
        if self.path == '/health':
            self.send_json({'ready': True, 'model_parameters': parameter_count,
                            'native_pid': getattr(getattr(self.server.engine, 'worker', None), 'pid', None),
                            'template_sha256': self.server.engine.template_hash})
        else:
            self.send_json({'error': 'Unknown route'}, 404)

    def event(self, profile, identity, delta=None, finish=None, usage=None, native_calls=0):
        value = copy.deepcopy(profile)
        value.update(identity)
        if delta is not None:
            value['choices'][0]['delta'] = delta
        if finish is not None:
            value['choices'][0]['finish_reason'] = finish
        if usage is not None:
            value['usage'] = usage
        self.wfile.write(b'data: ' + json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode() + b'\n\n')
        self.wfile.flush()
        print(json.dumps({'event': 'sse_flushed', 'id': identity['id'], 'native_decode_calls': native_calls,
                          'has_content': bool(delta and delta.get('content')), 'has_finish': finish is not None}), file=sys.stderr, flush=True)

    def do_POST(self):
        if self.path != '/v1/chat/completions':
            self.send_json({'error': 'Unknown route'}, 404)
            return
        try:
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length <= 1048576:
                raise ValueError('BODY_SIZE_OUT_OF_SCOPE')
            request = json.loads(self.rfile.read(length))
            prepared = self.server.engine.validate(request)
        except (ValueError, TypeError, KeyError) as error:
            self.send_json({'error': {'message': str(error)}}, 400)
            return
        identity = {'id': 'chatcmpl-' + secrets.token_hex(11), 'created': int(time.time())}
        profile = CHAT_SPEC['wire_profile']
        try:
            with self.server.engine.lock:
                if request.get('stream', False):
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/event-stream')
                    self.send_header('Cache-Control', 'no-cache')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    first = True
                    for item in self.server.engine.infer(prepared, identity['id']):
                        if 'delta' in item:
                            delta = {'content': item['delta']}
                            if first:
                                delta['role'] = 'assistant'
                            self.event(profile['first' if first else 'middle'], identity, delta=delta, native_calls=item['native_calls'])
                            first = False
                        else:
                            self.event(profile['finish'], identity, delta={}, finish=item['finish_reason'], native_calls=item['native_calls'])
                            if request.get('stream_options', {}).get('include_usage', False):
                                self.event(profile['usage'], identity, usage=item['usage'], native_calls=item['native_calls'])
                    self.wfile.write(b'data: [DONE]\n\n')
                    self.wfile.flush()
                    self.close_connection = True
                else:
                    content = ''
                    for item in self.server.engine.infer(prepared, identity['id']):
                        if 'delta' in item:
                            content += item['delta']
                        else:
                            final = item
                    response = copy.deepcopy(profile['completion'])
                    response.update(identity)
                    response['choices'][0]['message']['content'] = content
                    response['choices'][0]['finish_reason'] = final['finish_reason']
                    response['usage'] = final['usage']
                    self.send_json(response)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as error:
            print(json.dumps({'event': 'inference_failed', 'detail': str(error)}), file=sys.stderr, flush=True)
            self.close_connection = True


def serve_chat():
    global parameter_count
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=1235)
    arguments = parser.parse_args()
    # HTTP sessions overlap; every native RPC executes on the same C++ worker
    # thread with independent context/sampler state for each session.
    server_type = ThreadingHTTPServer if CHAT_SPEC.get('native_worker_path') else HTTPServer
    server = server_type(('127.0.0.1', arguments.port), ChatHandler)
    server.engine = NativeWorkerEngine() if CHAT_SPEC.get('native_worker_path') else NativeChatEngine()
    if CHAT_SPEC.get('native_worker_path'):
        parameter_count = server.engine.metadata['model_parameters']
    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        print(json.dumps({'ready': True, 'port': arguments.port, 'parameters': parameter_count}), flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if CHAT_SPEC.get('native_worker_path'):
            server.engine.close()
        else:
            lib.llama_sampler_free(sampler)
            lib.llama_free(ctx)
            lib.llama_model_free(model)
            lib.llama_backend_free()
