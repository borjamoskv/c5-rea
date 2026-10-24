"""Native inference reconstruction: derive FFI bindings from a pinned public ABI.

Weights and llama.cpp are explicit dependencies, not inferred from example text.
No original-server calls or saved answers are emitted into the implementation.
"""

import ast
import ctypes
import hashlib
import json
import os
import random
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from evidence_schema import BinaryTriageReport, EvidenceEnvelopeV2


BACKEND = "native-llama-c-api-v1"
RECORDS = ("llama_batch", "llama_model_params", "llama_context_params")
FUNCTIONS = (
    "ggml_backend_load_all_from_path", "llama_backend_init", "llama_backend_free",
    "llama_model_default_params", "llama_context_default_params",
    "llama_model_load_from_file", "llama_init_from_model", "llama_model_get_vocab",
    "llama_model_n_params", "llama_get_memory", "llama_memory_clear",
    "llama_tokenize", "llama_batch_get_one", "llama_decode",
    "llama_sampler_init_greedy", "llama_sampler_sample", "llama_vocab_is_eog",
    "llama_token_to_piece", "llama_sampler_free", "llama_free", "llama_model_free",
)


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def inspect_abi(headers, records=RECORDS, functions=FUNCTIONS):
    headers = Path(headers).resolve()
    command = ["clang", "-x", "c", "-fsyntax-only", "-I", str(headers), str(headers / "llama.h")]
    process = subprocess.run(command[:3] + ["-Xclang", "-ast-dump=json"] + command[3:], capture_output=True, text=True, timeout=30)
    if process.returncode:
        raise ValueError("Cannot inspect native ABI: " + process.stderr[:1000])
    required_records, required_functions = records, functions
    records, functions = {}, {}

    def visit(node):
        name = node.get("name")
        if node.get("kind") == "RecordDecl" and name in required_records and node.get("completeDefinition"):
            records[name] = [(field["name"], field["type"]) for field in node.get("inner", []) if field.get("kind") == "FieldDecl"]
        if node.get("kind") == "FunctionDecl" and name in required_functions:
            functions[name] = {
                "return": node["type"]["qualType"].split("(", 1)[0].strip(),
                "arguments": [arg["type"] for arg in node.get("inner", []) if arg.get("kind") == "ParmVarDecl"],
            }
        for child in node.get("inner", []):
            visit(child)

    visit(json.loads(process.stdout))
    if set(records) != set(required_records) or set(functions) != set(required_functions):
        raise ValueError("Required native declarations missing")
    layout = subprocess.run(command[:3] + ["-Xclang", "-fdump-record-layouts-complete"] + command[3:], capture_output=True, text=True, timeout=30)
    sizes = {}
    for block in layout.stdout.split("*** Dumping AST Record Layout"):
        for name in required_records:
            if "| struct " + name + "\n" in block:
                sizes[name] = int(re.search(r"\[sizeof=(\d+),", block).group(1))
    if set(sizes) != set(required_records):
        raise ValueError("Native structure sizes unavailable")
    return {"records": records, "functions": functions, "sizes": sizes,
            "headers_sha256": {path.name: file_hash(path) for path in sorted(headers.glob("*.h"))}}


def _ctype(declaration):
    if isinstance(declaration, str):
        value = declaration
    else:
        value = declaration.get("desugaredQualType", declaration["qualType"])
    if "*" in value or value == "llama_memory_t":
        return "ct.c_void_p"
    if value.startswith("enum "):
        return "ct.c_int"
    if value.startswith("struct ") and value[7:] in RECORDS:
        return value[7:]
    types = {
        "void": "None", "bool": "ct.c_bool", "_Bool": "ct.c_bool",
        "int": "ct.c_int", "int32_t": "ct.c_int32", "llama_token": "ct.c_int32",
        "unsigned int": "ct.c_uint", "uint32_t": "ct.c_uint32",
        "unsigned long": "ct.c_ulong", "unsigned long long": "ct.c_ulonglong",
        "size_t": "ct.c_size_t", "uint64_t": "ct.c_uint64",
        "float": "ct.c_float", "double": "ct.c_double",
    }
    if value not in types:
        raise ValueError("Unsupported ABI type: " + value)
    return types[value]


def native_program(specification):
    """Build a program AST from ABI declarations and a generic decode dataflow.

    This emits no application source template, prompt lookup, HTTP client, or
    LM Studio launcher. The native forward pass is performed by libllama.
    """
    if type(specification.get('context_length')) is not int or not 1 <= specification['context_length'] <= 131072:
        raise ValueError('Invalid native context length')
    if type(specification.get('gpu_layers', 999)) is not int or not 0 <= specification.get('gpu_layers', 999) <= 999:
        raise ValueError('Invalid native GPU layer count')
    def expression(source):
        return ast.parse(source, mode="eval").body

    def statement(source):
        return ast.parse(source).body[0]

    def assignment(target, value):
        return statement(target + " = " + value)

    abi = specification["abi"]
    body = [ast.Import([ast.alias("ctypes", "ct"), ast.alias("json"), ast.alias("sys"), ast.alias("time")])]
    for name in RECORDS:
        fields = ast.List([
            ast.Tuple([ast.Constant(field), expression(_ctype(declaration))], ast.Load())
            for field, declaration in abi["records"][name]
        ], ast.Load())
        body.append(ast.ClassDef(name=name, bases=[expression("ct.Structure")], keywords=[], body=[
            ast.Assign([ast.Name("_fields_", ast.Store())], fields),
        ], decorator_list=[]))
        body.append(ast.Assert(expression("ct.sizeof(" + name + ") == " + str(abi["sizes"][name])), ast.Constant("Native ABI size mismatch")))
    body.append(assignment("lib", "ct.CDLL(" + repr(specification["library_path"]) + ")"))
    for name in FUNCTIONS:
        signature = abi["functions"][name]
        body.append(assignment("lib." + name + ".restype", _ctype(signature["return"])))
        body.append(assignment("lib." + name + ".argtypes", "[" + ", ".join(_ctype(item) for item in signature["arguments"]) + "]"))
    initialization = [
        "lib.ggml_backend_load_all_from_path(" + repr(str(Path(specification["library_path"]).parent).encode()) + ")",
        "lib.llama_backend_init()",
        "mp = lib.llama_model_default_params()",
        "mp.n_gpu_layers = " + str(specification.get('gpu_layers', 999)),
        "mp.vocab_only = False", "mp.no_alloc = False",
        "model = lib.llama_model_load_from_file(" + repr(specification["model_path"].encode()) + ", mp)",
        "assert model, 'MODEL_LOAD_FAILED'",
        "cp = lib.llama_context_default_params()",
        "cp.n_ctx = " + str(specification["context_length"]),
        "cp.n_batch = 256", "cp.n_ubatch = 64", "cp.n_seq_max = 1",
        "cp.n_threads = 6", "cp.n_threads_batch = 6", "cp.flash_attn_type = 1",
        "ctx = lib.llama_init_from_model(model, cp)",
        "assert ctx, 'CONTEXT_LOAD_FAILED'",
        "vocab = lib.llama_model_get_vocab(model)",
        "sampler = lib.llama_sampler_init_greedy()",
        "assert sampler, 'SAMPLER_LOAD_FAILED'",
        "parameter_count = lib.llama_model_n_params(model)",
        "assert parameter_count > 0, 'NO_MODEL_PARAMETERS'",
        "requests = json.load(sys.stdin)", "results = []",
    ]
    if specification.get('cpu_only'):
        position = initialization.index("ctx = lib.llama_init_from_model(model, cp)")
        initialization[position:position] = ["cp.offload_kqv = False", "cp.op_offload = False"]
    if specification.get('memory_policy') == 'mmap-no-repack':
        position = next(i for i, line in enumerate(initialization) if line.startswith('model = '))
        initialization[position:position] = ["mp.use_extra_bufts = False", "mp.load_mode = 1"]
    body.extend(statement(source) for source in initialization)
    loop = [statement(source) for source in [
        "print('native request ' + str(len(results) + 1) + '/' + str(len(requests)), file=sys.stderr, flush=True)",
        "started = time.monotonic()",
        "assert isinstance(request['prompt'], str), 'PROMPT_MUST_BE_TEXT'",
        "assert request.get('temperature', 0) == 0, 'ONLY_GREEDY_IS_CERTIFIABLE'",
        "limit = request.get('max_tokens', 16)",
        "assert isinstance(limit, int) and 1 <= limit <= 64, 'TOKEN_LIMIT_OUT_OF_SCOPE'",
        "raw = request['prompt'].encode('utf-8')",
        "capacity = max(32, len(raw) + 8)",
        "tokens = (ct.c_int32 * capacity)()",
        "count = lib.llama_tokenize(vocab, raw, len(raw), tokens, capacity, True, True)",
        "assert count > 0 and count + limit <= cp.n_ctx, 'PROMPT_OUT_OF_SCOPE'",
        "lib.llama_memory_clear(lib.llama_get_memory(ctx), True)",
        "batch = lib.llama_batch_get_one(tokens, count)",
        "assert lib.llama_decode(ctx, batch) == 0, 'PREFILL_FAILED'",
        "decode_calls = 1", "output = bytearray()", "token_ids = []", "sampled = []",
        "finish = 'length'",
    ]]
    decode_loop = [
        statement("token = lib.llama_sampler_sample(sampler, ctx, -1)"),
        statement("sampled.append(token)"),
        ast.If(expression("lib.llama_vocab_is_eog(vocab, token)"), [statement("finish = 'stop'"), ast.Break()], []),
        statement("token_ids.append(token)"),
        statement("piece = ct.create_string_buffer(4096)"),
        statement("size = lib.llama_token_to_piece(vocab, token, piece, len(piece), 0, True)"),
        statement("assert 0 <= size <= len(piece), 'TOKEN_PIECE_OUT_OF_SCOPE'"),
        statement("output.extend(piece.raw[:size])"),
        statement("current = (ct.c_int32 * 1)(token)"),
        statement("assert lib.llama_decode(ctx, lib.llama_batch_get_one(current, 1)) == 0, 'DECODE_FAILED'"),
        statement("decode_calls += 1"),
    ]
    loop.append(ast.For(ast.Name("step", ast.Store()), expression("range(limit)"), decode_loop, []))
    loop.append(statement("results.append({'text': output.decode('utf-8', errors='replace'), 'prompt_tokens': count, 'completion_tokens': len(sampled), 'token_ids': token_ids, 'sampled_ids': sampled, 'finish_reason': finish, 'decode_calls': decode_calls, 'seconds': time.monotonic() - started})"))
    body.append(ast.Try(body=[ast.For(ast.Name("request", ast.Store()), expression("requests"), loop, [])], handlers=[], orelse=[], finalbody=[
        statement("lib.llama_sampler_free(sampler)"), statement("lib.llama_free(ctx)"),
        statement("lib.llama_model_free(model)"), statement("lib.llama_backend_free()"),
    ]))
    body.append(statement("print(json.dumps({'model_parameters': parameter_count, 'results': results}, ensure_ascii=False))"))
    return ast.fix_missing_locations(ast.Module(body=body, type_ignores=[]))


def generate_native(envelope, output_directory):
    specification = envelope.clean_room_specification
    if specification.get("backend") != BACKEND:
        raise ValueError("Native inference evidence required")
    root = Path(output_directory)
    root.mkdir(parents=True, exist_ok=True)
    artifact = root / "native_inference.py"
    artifact.write_text("#!/usr/bin/env python3\n" + ast.unparse(native_program(specification)) + "\n")
    artifact.chmod(0o755)
    specification["implementation_sha256"] = file_hash(artifact)
    return [artifact]


def inspect_native(model_path, library_path, headers, reference_url, model_id, context_length=1024):
    model_path, library_path = Path(model_path).resolve(), Path(library_path).resolve()
    with model_path.open("rb") as source:
        if source.read(4) != b"GGUF":
            raise ValueError("A real local GGUF is required")
    parsed = urllib.parse.urlsplit(reference_url)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("A local LM Studio reference is required")
    abi = inspect_abi(headers)
    native = ctypes.CDLL(str(library_path))
    for name in FUNCTIONS:
        getattr(native, name)
    weights_hash = file_hash(model_path)
    specification = {
        "backend": BACKEND, "model_path": str(model_path), "weights_sha256": weights_hash,
        "library_path": str(library_path), "library_sha256": file_hash(library_path),
        "native_dependencies": {str(path): file_hash(path) for path in sorted(library_path.parent.glob("*.dylib"))},
        "abi": abi, "reference_url": reference_url, "reference_model": model_id,
        "context_length": context_length,
        "lms_path": shutil.which("lms"),
        "scope": "real GGUF inference through native llama.cpp; raw text completions; greedy temperature=0; max 64 tokens; no GUI, chat or stochastic equivalence",
        "reconstruction_kind": "native-ABI composition with existing weights and inference library, not recovery of weights or proprietary engine source",
    }
    return EvidenceEnvelopeV2(
        target=BinaryTriageReport(str(model_path), weights_hash, model_path.stat().st_size, "GGUF", None),
        clean_room_specification=specification,
    )


def _json_request(base, path, payload=None, timeout=120):
    request = urllib.request.Request(
        base.rstrip("/") + path,
        data=None if payload is None else json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def inference_cases(seed):
    """New inputs; never expected answers or generated application code."""
    rng = random.Random(seed)
    nonce = "".join(rng.choices("abcdef0123456789", k=20))
    prompts = [
        "def add(a, b):\n    return",
        "The capital of France is",
        "Los colores primarios son",
        "def factorial(n):\n    if n <= 1:\n        return 1\n    return",
        "const square = (x) =>",
        "The opposite of hot is",
        "SELECT name FROM users WHERE",
        "日曜日の次の日は",
        "def label_" + nonce + "(value):\n    return",
        str(rng.randrange(10, 99)) + " + " + str(rng.randrange(10, 99)) + " =",
        "Complete this identifier: " + nonce + "_result =",
    ]
    prompts.append(prompts[0])  # Repeated input checks reset and reference stability.
    return [{"prompt": prompt, "max_tokens": 16, "temperature": 0} for prompt in prompts]


def _reference_identity(specification):
    """Resolve executable identities without recording private backend arguments."""
    port = urllib.parse.urlsplit(specification["reference_url"]).port or 80
    listener = subprocess.run(["lsof", "-nP", "-iTCP:" + str(port), "-sTCP:LISTEN", "-Fp"], capture_output=True, text=True, timeout=10)
    pids = [int(line[1:]) for line in listener.stdout.splitlines() if line.startswith("p")]
    library = ctypes.CDLL("/usr/lib/libproc.dylib")
    library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    library.proc_pidpath.restype = ctypes.c_int
    identities = []
    for pid in pids:
        buffer = ctypes.create_string_buffer(4096)
        if library.proc_pidpath(pid, buffer, len(buffer)) > 0:
            path = Path(os.fsdecode(buffer.value))
            if path.name == "LM Studio" and "LM Studio.app" in path.parts:
                identities.append({"pid": pid, "executable": str(path), "sha256": file_hash(path)})
    if not identities:
        raise ValueError("REFERENCE_LISTENER_IS_NOT_LM_STUDIO")
    processes = subprocess.run(["ps", "-axo", "pid,args"], capture_output=True, text=True, timeout=10)
    for line in processes.stdout.splitlines():
        if "/llama-server " not in line:
            continue
        try:
            pid_text, arguments_text = line.strip().split(None, 1)
            arguments = shlex.split(arguments_text)
            if "--model" in arguments and arguments[arguments.index("--model") + 1] == specification["model_path"]:
                engine = Path(arguments[0])
                if ".lmstudio" in engine.parts and engine.name == "llama-server":
                    return {"listeners": identities, "inference_engine": str(engine), "engine_pid": int(pid_text), "engine_sha256": file_hash(engine), "weights_path": specification["model_path"]}
        except (ValueError, OSError):
            continue
    raise ValueError("ORIGINAL_MODEL_PROCESS_NOT_FOUND")


def audit_native(envelope, implementation, manage_reference=False, output_directory=None, seed=None):
    """Execute a live sequential reference/native comparison with restoration.

    Managing LM Studio is opt-in. The original server is unavailable throughout
    candidate inference; its initial server/model state is restored in finally.
    """
    specification = envelope.clean_room_specification
    result = {"status": "INCOMPLETE", "scope": specification.get("scope"), "verified_cases": 0, "coverage_percent": 0.0,
              "proof_kind": "exact bounded raw-completion comparison; not a clone of LM Studio"}
    if specification.get("backend") != BACKEND:
        return {**result, "reason": "NO_NATIVE_INFERENCE_SPECIFICATION"}
    if not manage_reference:
        return {**result, "reason": "EXPLICIT_REFERENCE_LIFECYCLE_MANAGEMENT_REQUIRED"}
    root = Path(output_directory or Path(implementation).parent / "native_verification").resolve()
    root.mkdir(parents=True, exist_ok=True)
    candidate = Path(implementation).resolve()
    base = specification["reference_url"]
    lms = specification.get("lms_path")
    stopped, loaded_by_audit, reference_unloaded = False, False, False
    initially_loaded = False
    lifecycle = []

    def finish(status, reason, **details):
        result.update({"status": status, "reason": reason, **details})
        return result

    def cli(*arguments):
        if not lms:
            raise ValueError("LM_STUDIO_CLI_UNAVAILABLE")
        with tempfile.TemporaryFile() as output:
            process = subprocess.run([lms, *arguments], stdout=output, stderr=output, timeout=90)
            output.seek(0)
            text = output.read().decode(errors="replace")
        lifecycle.append({"command": [lms, *arguments], "returncode": process.returncode})
        if process.returncode:
            raise ValueError("Reference lifecycle command failed: " + text[-500:])

    try:
        if not candidate.is_file() or ast.dump(ast.parse(candidate.read_text())) != ast.dump(native_program(specification)):
            return finish("FAIL", "NOT_THE_GENERATED_NATIVE_IMPLEMENTATION")
        if file_hash(candidate) != specification.get("implementation_sha256"):
            return finish("FAIL", "IMPLEMENTATION_CHANGED")
        if file_hash(specification["model_path"]) != specification["weights_sha256"]:
            return finish("FAIL", "WEIGHTS_CHANGED")
        if any(file_hash(path) != expected for path, expected in specification["native_dependencies"].items()):
            return finish("FAIL", "NATIVE_DEPENDENCY_CHANGED")
        models = _json_request(base, "/api/v1/models")["models"]
        target = next(model for model in models if model["key"] == specification["reference_model"])
        initially_loaded = bool(target["loaded_instances"])
        if initially_loaded:
            if target["loaded_instances"][0]["config"]["context_length"] != specification["context_length"]:
                return finish("INCOMPLETE", "REFERENCE_CONTEXT_DOES_NOT_MATCH")
        else:
            _json_request(base, "/api/v1/models/load", {
                "model": specification["reference_model"], "context_length": specification["context_length"],
                "eval_batch_size": 2048, "flash_attention": True, "echo_load_config": True,
            })
            loaded_by_audit = True
        identity = _reference_identity(specification)
        seed = secrets.randbits(64) if seed is None else seed
        requests = inference_cases(seed)
        originals = []
        for request in requests:
            originals.append(_json_request(base, "/v1/completions", {
                **request, "model": specification["reference_model"], "seed": 42,
                "repeat_penalty": 1.0, "stream": False,
            }))
        (root / "original.json").write_text(json.dumps({"identity": identity, "requests": requests, "responses": originals}, ensure_ascii=False, indent=2))
        if originals[0]["choices"][0]["text"] != originals[-1]["choices"][0]["text"]:
            return finish("INCOMPLETE", "REFERENCE_NOT_DETERMINISTIC")
        # Never keep two 9 GB models loaded simultaneously on a small machine.
        cli("unload", specification["reference_model"])
        reference_unloaded = True
        # CLI completion can precede process teardown. Wait for actual release,
        # rather than allowing two models to overlap in memory.
        deadline = time.monotonic() + 60
        while True:
            process_state = subprocess.run(["ps", "-p", str(identity["engine_pid"]), "-o", "rss="], capture_output=True, text=True, timeout=10)
            if process_state.returncode != 0:
                break
            if time.monotonic() >= deadline:
                return finish("INCOMPLETE", "REFERENCE_MODEL_PROCESS_DID_NOT_EXIT")
            time.sleep(0.5)
        result["reference_model_process_exited"] = True
        cli("server", "stop")
        stopped = True
        try:
            _json_request(base, "/v1/models", timeout=2)
        except (OSError, urllib.error.URLError):
            reference_offline = True
        else:
            return finish("FAIL", "REFERENCE_STILL_REACHABLE")
        input_path = root / "inputs.json"
        input_path.write_text(json.dumps(requests, ensure_ascii=False))
        started = time.monotonic()
        with input_path.open("rb") as inputs, (root / "candidate.json").open("wb") as output, (root / "native.log").open("wb") as log:
            process = subprocess.run([sys.executable, "-I", "-S", "-X", "faulthandler", str(candidate)], stdin=inputs, stdout=output, stderr=log, timeout=300)
        if process.returncode:
            return finish("FAIL", "NATIVE_INFERENCE_PROCESS_FAILED", returncode=process.returncode, log_path=str(root / "native.log"))
        measured = json.loads((root / "candidate.json").read_text())
        if measured["model_parameters"] <= 0 or len(measured["results"]) != len(requests):
            return finish("FAIL", "NO_REAL_INFERENCE_RESULTS")
        comparisons = []
        for request, original, generated in zip(requests, originals, measured["results"]):
            actual = original["choices"][0]
            fields = {
                "text": generated["text"] == actual["text"],
                "finish_reason": generated["finish_reason"] == actual["finish_reason"],
                "prompt_tokens": generated["prompt_tokens"] == original["usage"]["prompt_tokens"],
                "completion_tokens": generated["completion_tokens"] == original["usage"]["completion_tokens"],
                "native_decode_executed": generated["decode_calls"] > 0 and bool(generated["sampled_ids"]),
            }
            comparisons.append({"request": request, "checks": fields, "matches": all(fields.values()), "original_text": actual["text"], "candidate_text": generated["text"]})
        unchanged = (file_hash(candidate) == specification["implementation_sha256"]
                     and file_hash(specification["model_path"]) == specification["weights_sha256"]
                     and all(file_hash(path) == expected for path, expected in specification["native_dependencies"].items()))
        verified = sum(case["matches"] for case in comparisons)
        result.update({
            "status": "PASS" if verified == len(requests) and unchanged else "FAIL",
            "reason": "ALL_LIVE_INFERENCE_CASES_MATCH" if verified == len(requests) and unchanged else "INFERENCE_MISMATCH_OR_ARTIFACT_CHANGED",
            "verification_seed": seed, "total_cases": len(requests), "verified_cases": verified,
            "tested_parameters": {"endpoint": "/v1/completions", "temperature": 0, "max_tokens": 16,
                                  "context_length": specification["context_length"], "repeat_penalty": 1.0},
            "coverage_percent": round(100 * verified / len(requests), 2),
            "reference_identity": identity, "reference_offline_during_candidate": reference_offline,
            "native_model_parameters": measured["model_parameters"], "candidate_seconds": time.monotonic() - started,
            "weights_sha256": specification["weights_sha256"], "implementation_sha256": file_hash(candidate),
            "cases": comparisons,
        })
    except (OSError, ValueError, KeyError, StopIteration, subprocess.TimeoutExpired, urllib.error.URLError) as error:
        result.update({"status": "INCOMPLETE", "reason": type(error).__name__, "detail": str(error)})
    finally:
        try:
            if stopped:
                cli("server", "start")
                stopped = False
            if initially_loaded and reference_unloaded:
                _json_request(base, "/api/v1/models/load", {"model": specification["reference_model"], "context_length": specification["context_length"]})
            elif loaded_by_audit and not reference_unloaded:
                cli("unload", specification["reference_model"])
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            result.update({"status": "INCOMPLETE", "restore_error": str(error)})
        result["lifecycle"] = lifecycle
        (root / "verification.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
    return result


def reconstruct_native(model_path, library_path, headers, reference_url, model_id,
                       output_directory, manage_reference=False, context_length=1024):
    root = Path(output_directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    report_path = root / "verification.json"
    report_path.write_text(json.dumps({"status": "INCOMPLETE", "reason": "INSPECTING_NATIVE_DEPENDENCIES"}))
    envelope = inspect_native(model_path, library_path, headers, reference_url, model_id, context_length)
    candidate = generate_native(envelope, root)[0]
    (root / "evidence.json").write_text(envelope.model_dump_json(indent=2))
    report = audit_native(envelope, candidate, manage_reference=manage_reference, output_directory=root / "comparison")
    envelope.falsification_verdict = report["status"]
    (root / "evidence.json").write_text(envelope.model_dump_json(indent=2))
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    return {key: value for key, value in report.items() if key != "cases"}
