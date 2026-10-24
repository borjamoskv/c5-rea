"""Learn bounded byte-stream transducers and verify them against the real process.

This backend learns transition/output tables through queries. It does not contain
application-specific algorithms, saved responses, or an original-process wrapper.
PASS is always limited to the pinned invocation and the freshly executed corpus.
"""

import ast
import base64
import hashlib
import json
import os
import random
import secrets
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from evidence_schema import BinaryTriageReport, EvidenceEnvelopeV2


BACKEND = "learned-mealy-stdio-v1"
ALPHABET = tuple(bytes([i]) for i in range(256))


class UnsupportedBehavior(ValueError):
    """The observations cannot be represented by this backend's bounded model."""


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _encoded(data):
    return base64.b64encode(data).decode("ascii")


def _invoke(command, data, timeout=3.0):
    # A stdin-only contract: each invocation starts in a fresh, empty directory.
    with tempfile.TemporaryDirectory(prefix="c5-rea-run-") as directory:
        environment = {
            "PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
            "HOME": directory, "TMPDIR": directory,
        }
        try:
            root = Path(directory)
            (root / "stdin").write_bytes(data)
            # File-backed streams avoid pipe backpressure on large binary corpora
            # and bound memory while the parent waits with a real deadline.
            with (root / "stdin").open("rb") as source, (root / "stdout").open("wb") as output, (root / "stderr").open("wb") as error_output:
                process = subprocess.run(
                    command, stdin=source, stdout=output, stderr=error_output,
                    timeout=timeout, cwd=directory, env=environment, check=False,
                )
            if (root / "stdout").stat().st_size + (root / "stderr").stat().st_size > 4 * 1024 * 1024:
                return {"error": "OUTPUT_LIMIT"}
            return {
                "returncode": process.returncode,
                "stdout": _encoded((root / "stdout").read_bytes()),
                "stderr": _encoded((root / "stderr").read_bytes()),
            }
        except subprocess.TimeoutExpired:
            return {"error": "TIMEOUT"}
        except OSError as error:
            return {"error": type(error).__name__, "detail": str(error)}


class Oracle:
    def __init__(self, command, max_queries=20000):
        if not command:
            raise ValueError("An original executable and its arguments are required")
        executable = shutil.which(command[0])
        if executable is None:
            raise FileNotFoundError(command[0])
        self.command = [str(Path(executable).resolve()), *command[1:]]
        self.original_sha256 = digest(self.command[0])
        self.cache = {}
        self.max_queries = max_queries

    def query(self, data):
        if data not in self.cache:
            if len(self.cache) >= self.max_queries:
                raise UnsupportedBehavior("Query budget exceeded; no executable certified")
            result = _invoke(self.command, data)
            if result.get("returncode") != 0 or result.get("stderr") != "":
                raise UnsupportedBehavior("This learner requires successful, stderr-free stdin processing")
            self.cache[data] = base64.b64decode(result["stdout"])
        return self.cache[data]

    def residual(self, prefix, suffix):
        before, after = self.query(prefix), self.query(prefix + suffix)
        if not after.startswith(before):
            raise UnsupportedBehavior("Non-prefix-preserving output; a different synthesis backend is required")
        return after[len(before):]


def run_model(model, data):
    state = 0
    output = bytearray()
    for value in data:
        next_state, emitted = model["transitions"][state][value]
        output.extend(base64.b64decode(emitted))
        state = next_state
    return bytes(output)


def training_inputs():
    yield b""
    yield bytes(range(256))
    for symbol in ALPHABET:
        yield symbol * 2
        yield symbol * 3
    yield bytes(reversed(range(256)))
    randomizer = random.Random(49163)
    for _ in range(24):
        yield randomizer.randbytes(randomizer.randrange(1, 200))


def learn_transducer(command, max_states=32):
    """Closed, consistent observation table plus bounded counterexample search.

    There is no equivalence oracle: held-out execution is mandatory after learning.
    Unsupported/delayed-output commands are rejected rather than fabricated.
    """
    oracle = Oracle(command)
    if oracle.query(b""):
        raise UnsupportedBehavior("Nonempty terminal output is not supported by this Mealy backend")
    prefixes = [b""]
    suffixes = [b"\x00"]
    for _round in range(16):
        while True:
            rows = {}

            def row(prefix):
                if prefix not in rows:
                    rows[prefix] = tuple(oracle.residual(prefix, suffix) for suffix in suffixes)
                return rows[prefix]

            representative = {row(prefix): prefix for prefix in reversed(prefixes)}
            new_prefix = None
            for prefix in prefixes:
                for symbol in ALPHABET:
                    if row(prefix + symbol) not in representative:
                        new_prefix = prefix + symbol
                        break
                if new_prefix is not None:
                    break
            if new_prefix is not None:
                prefixes.append(new_prefix)
                if len({row(prefix) for prefix in prefixes}) > max_states:
                    raise UnsupportedBehavior("State limit exceeded")
                continue

            distinguishing_suffix = None
            for index, left in enumerate(prefixes):
                for right in prefixes[index + 1:]:
                    if row(left) != row(right):
                        continue
                    for symbol in ALPHABET:
                        if oracle.residual(left, symbol) != oracle.residual(right, symbol):
                            distinguishing_suffix = symbol
                            break
                        lhs, rhs = row(left + symbol), row(right + symbol)
                        if lhs != rhs:
                            position = next(i for i in range(len(lhs)) if lhs[i] != rhs[i])
                            distinguishing_suffix = symbol + suffixes[position]
                            break
                    if distinguishing_suffix is not None:
                        break
                if distinguishing_suffix is not None:
                    break
            if distinguishing_suffix is not None:
                suffixes.append(distinguishing_suffix)
                continue
            break

        representatives = []
        state_ids = {}
        for prefix in prefixes:
            if row(prefix) not in state_ids:
                state_ids[row(prefix)] = len(representatives)
                representatives.append(prefix)
        transitions = []
        for prefix in representatives:
            transitions.append([
                [state_ids[row(prefix + symbol)], _encoded(oracle.residual(prefix, symbol))]
                for symbol in ALPHABET
            ])
        model = {"backend": BACKEND, "transitions": transitions}
        counterexample = None
        for data in training_inputs():
            if run_model(model, data) != oracle.query(data):
                counterexample = data
                break
        if counterexample is None:
            break
        # First divergent prefix prevents a long random trace inflating the table.
        for length in range(1, len(counterexample) + 1):
            prefix = counterexample[:length]
            if prefix not in prefixes:
                prefixes.append(prefix)
            if run_model(model, prefix) != oracle.query(prefix):
                break
    else:
        raise UnsupportedBehavior("Learning did not converge within the refinement budget")

    for sample in (b"", bytes(range(256)), b"\x00\xff\x00"):
        repeated = _invoke(oracle.command, sample)
        if repeated != {"returncode": 0, "stdout": _encoded(oracle.query(sample)), "stderr": ""}:
            raise UnsupportedBehavior("Original is not deterministic under the tested invocation")
    if digest(oracle.command[0]) != oracle.original_sha256:
        raise UnsupportedBehavior("Original changed during learning")
    observations = [
        {"input_base64": _encoded(data), "output_base64": _encoded(output)}
        for data, output in sorted(oracle.cache.items())
    ]
    specification = {
        "backend": BACKEND, "original_argv": oracle.command,
        "original_sha256": oracle.original_sha256, "locale": "C",
        "scope": "fixed argv; binary stdin/stdout; fresh process; no filesystem, GUI, concurrency or other CLI options",
        "model": model, "learning_queries": len(observations),
        "observations_sha256": hashlib.sha256(json.dumps(observations, sort_keys=True).encode()).hexdigest(),
    }
    from rea_orchestrator import calculate_entropy
    target = BinaryTriageReport(
        target_path=oracle.command[0], sha256=oracle.original_sha256,
        file_size_bytes=Path(oracle.command[0]).stat().st_size,
        architecture="observed-executable", entropy_shannon=calculate_entropy(Path(oracle.command[0])),
    )
    return EvidenceEnvelopeV2(target=target, clean_room_specification=specification), observations


def _program_ast(model):
    """Compile learned transitions to a standalone Python AST, with no oracle link."""
    table = model.get("transitions")
    if not isinstance(table, list) or not 1 <= len(table) <= 32:
        raise ValueError("Invalid model states")
    for transitions in table:
        if len(transitions) != 256:
            raise ValueError("Every byte must have a learned transition")
        for transition in transitions:
            destination, output = transition
            if type(destination) is not int or not 0 <= destination < len(table):
                raise ValueError("Invalid destination state")
            if len(base64.b64decode(output, validate=True)) > 1024:
                raise ValueError("Emission limit exceeded")

    def name(value, store=False):
        return ast.Name(value, ast.Store() if store else ast.Load())

    def attr(value, attribute):
        return ast.Attribute(value, attribute, ast.Load())

    def call(function, *arguments):
        return ast.Call(function, list(arguments), [])

    def literal(value):
        if isinstance(value, list):
            return ast.List([literal(item) for item in value], ast.Load())
        return ast.Constant(value)

    def assign(identifier, value):
        return ast.Assign([name(identifier, True)], value)

    def cell(identifier):
        return ast.Subscript(ast.Subscript(name(identifier), name("state"), ast.Load()), name("symbol"), ast.Load())

    destinations = [[entry[0] for entry in transitions] for transitions in table]
    emissions = [[base64.b64decode(entry[1]) for entry in transitions] for transitions in table]
    module = ast.Module(body=[
        ast.Import([ast.alias("sys")]),
        assign("destinations", literal(destinations)),
        assign("emissions", literal(emissions)),
        assign("state", ast.Constant(0)),
        ast.While(ast.Constant(True), [
            assign("data", call(attr(attr(attr(name("sys"), "stdin"), "buffer"), "read"), ast.Constant(65536))),
            ast.If(ast.UnaryOp(ast.Not(), name("data")), [ast.Break()], []),
            assign("output", call(name("bytearray"))),
            ast.For(name("symbol", True), name("data"), [
                ast.Expr(call(attr(name("output"), "extend"), cell("emissions"))),
                assign("state", cell("destinations")),
            ], []),
            ast.Expr(call(attr(attr(attr(name("sys"), "stdout"), "buffer"), "write"), name("output"))),
        ], []),
        ast.Expr(call(attr(attr(attr(name("sys"), "stdout"), "buffer"), "flush"))),
    ], type_ignores=[])
    return ast.fix_missing_locations(module)


def generate_executable(envelope, out_dir):
    specification = envelope.clean_room_specification
    if specification.get("backend") != BACKEND:
        raise UnsupportedBehavior("No learned executable model; contracts cannot substitute for an implementation")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "implementation.py"
    source = "#!/usr/bin/env python3\n" + ast.unparse(_program_ast(specification["model"])) + "\n"
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    specification["implementation_sha256"] = digest(path)
    return [path]


def verification_inputs(seed):
    """Independent generated inputs. Expected outputs always come from live execution."""
    yield b""
    for symbol in ALPHABET:
        yield symbol
    yield bytes(range(256))
    yield bytes(reversed(range(256)))
    # Each possible adjacent pair appears; also exercises chunk boundaries.
    yield b"".join(bytes([left, right]) for left in range(256) for right in range(256))
    yield b"\x00" * 65535 + bytes(range(256)) * 257
    randomizer = random.Random(seed)
    for _ in range(96):
        length = randomizer.randrange(0, 8193)
        alphabet = randomizer.sample(range(256), randomizer.randrange(1, 33))
        yield bytes(randomizer.choices(alphabet, k=length))


def audit_behavior(envelope, implementation, seed=None):
    specification = envelope.clean_room_specification
    result = {
        "status": "INCOMPLETE", "scope": specification.get("scope"),
        "verified_cases": 0, "coverage_percent": 0.0,
        "proof_kind": "bounded live differential execution, not universal equivalence",
    }
    if specification.get("backend") != BACKEND:
        return {**result, "reason": "NO_EXECUTABLE_BEHAVIOR_SPECIFICATION"}
    path = Path(implementation).resolve()
    try:
        command = specification["original_argv"]
        if not command or digest(command[0]) != specification["original_sha256"]:
            return {**result, "status": "FAIL", "reason": "ORIGINAL_DIGEST_MISMATCH"}
        if envelope.target.sha256 != specification["original_sha256"] or str(Path(envelope.target.target_path).resolve()) != command[0]:
            return {**result, "status": "FAIL", "reason": "TARGET_BINDING_MISMATCH"}
        if path == Path(command[0]).resolve() or digest(path) == specification["original_sha256"]:
            return {**result, "status": "FAIL", "reason": "ORIGINAL_IS_NOT_A_RECONSTRUCTION"}
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if ast.dump(tree) != ast.dump(_program_ast(specification["model"])):
            return {**result, "status": "FAIL", "reason": "NOT_A_STANDALONE_COMPILED_MODEL"}
        if digest(path) != specification.get("implementation_sha256"):
            return {**result, "status": "FAIL", "reason": "IMPLEMENTATION_DIGEST_MISMATCH"}
    except (OSError, ValueError, KeyError, IndexError, TypeError, SyntaxError) as error:
        return {**result, "status": "FAIL", "reason": "INVALID_OR_MISSING_ARTIFACT", "detail": str(error)}

    from existence_gate import run_existence_gap_audit
    gate = run_existence_gap_audit(str(path))
    if gate["verdict"] != "PASS":
        return {**result, "status": "FAIL", "reason": "EXISTENCE_GAP", "gate": gate}
    seed = secrets.randbits(64) if seed is None else seed
    inputs = list(verification_inputs(seed))
    original_hash, candidate_hash = digest(command[0]), digest(path)

    def compare(data):
        original = _invoke(command, data)
        candidate = _invoke([sys.executable, "-I", "-S", str(path)], data)
        return {
            "input_sha256": hashlib.sha256(data).hexdigest(), "input_bytes": len(data),
            "input_base64": _encoded(data), "original": original, "candidate": candidate,
            "matches": original == candidate and "error" not in original and "error" not in candidate,
        }

    with ThreadPoolExecutor(max_workers=8) as pool:
        comparisons = list(pool.map(compare, inputs))
    verified = sum(comparison["matches"] for comparison in comparisons)
    try:
        unchanged = digest(command[0]) == original_hash and digest(path) == candidate_hash
    except OSError:
        unchanged = False
    result.update({
        "status": "PASS" if verified == len(inputs) and unchanged else "FAIL",
        "reason": "ALL_DECLARED_TESTS_MATCH" if verified == len(inputs) and unchanged else "BEHAVIOR_MISMATCH_OR_ARTIFACT_CHANGED",
        "verification_seed": seed, "total_cases": len(inputs), "verified_cases": verified,
        "coverage_percent": round(100 * verified / len(inputs), 2),
        "original_argv": command, "original_sha256": original_hash,
        "implementation_sha256": candidate_hash,
        "model_states": len(specification["model"]["transitions"]),
        "cases": comparisons,
    })
    return result


def reconstruct(command, output_directory):
    output_directory = Path(output_directory).resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    report_path = output_directory / "verification.json"
    report_path.write_text(json.dumps({"status": "INCOMPLETE", "reason": "LEARNING_IN_PROGRESS"}))
    try:
        envelope, observations = learn_transducer(command)
    except (UnsupportedBehavior, OSError, ValueError) as error:
        report_path.write_text(json.dumps({"status": "INCOMPLETE", "reason": str(error)}))
        raise
    implementation = generate_executable(envelope, output_directory)[0]
    evidence_path = output_directory / "evidence.json"
    evidence_path.write_text(envelope.model_dump_json(indent=2))
    (output_directory / "observations.json").write_text(json.dumps(observations, indent=2))
    report = audit_behavior(envelope, implementation)
    envelope.falsification_verdict = report["status"]
    evidence_path.write_text(envelope.model_dump_json(indent=2))
    report.update({"evidence_path": str(evidence_path), "implementation_path": str(implementation), "report_path": str(report_path)})
    report_path.write_text(json.dumps(report, indent=2))
    return {key: value for key, value in report.items() if key != "cases"}
