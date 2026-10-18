#!/usr/bin/env python3
"""
Existence-Gap Gate (Anti-Vibe-Coding & Slopsquatting Firewall) - C5-REAL Ring-0.
Audits synthesized or LLM-generated code (Python, TypeScript/JS, Rust) in <15ms with
Zero External Dependencies (100% Python Standard Library).

Detects and blocks:
1. Hallucinated / Slopsquatted packages & unverified imports (AST + Manifest check).
2. Truncation stubs & lazy LLM placeholders (TODO, FIXME, pass-only bodies, unimplemented!()).
3. Syntax & structural corruption before code touches git or production.
"""

import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, Any, List, Set

# Known high-risk LLM hallucinated package patterns (Slopsquatting signatures)
SLOPSQUAT_PATTERNS = [
    re.compile(r"^(?:openai|anthropic|langchain|llama)[-_](?:utils|helper|wrapper| official|magic|auto|fast)$", re.I),
    re.compile(r"^(?:react|next|vue)[-_](?:super|magic|auto|ai)[-_]", re.I),
    re.compile(r"^(?:py|node|rust)[-_](?:chatgpt|claude|gemini)[-_](?:sdk|api|unofficial)$", re.I),
]

# Truncation / lazy LLM comment markers
TRUNCATION_MARKERS = [
    re.compile(r"//\s*\.\.\.\s*(?:rest of|existing|remaining)\s+code", re.I),
    re.compile(r"#\s*\.\.\.\s*(?:rest of|existing|remaining)\s+code", re.I),
    re.compile(r"/\*\s*\.\.\.\s*\*/"),
    re.compile(r"\b(?:TODO|FIXME):\s*(?:implement|add|complete|fill in)\b", re.I),
    re.compile(r"\bunimplemented!\(\)"),
]


def _get_python_stdlib_modules() -> Set[str]:
    std = set(getattr(sys, "stdlib_module_names", set()))
    std.update(sys.builtin_module_names)
    return std


def _discover_local_modules(root_dir: Path) -> Set[str]:
    local_mods: Set[str] = set()
    if not root_dir.is_dir():
        return local_mods
    for p in root_dir.rglob("*.py"):
        local_mods.add(p.stem)
        if p.parent != root_dir:
            local_mods.add(p.parent.name)
    return local_mods


def _discover_declared_dependencies(root_dir: Path) -> Set[str]:
    declared: Set[str] = set()
    if not root_dir.is_dir():
        return declared

    # package.json
    pkg_json = root_dir / "package.json"
    if pkg_json.is_file():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                for k in data.get(section, {}).keys():
                    declared.add(k)
                    declared.add(k.split("/")[0])
        except Exception:
            pass

    # pyproject.toml (lightweight regex parse to stay 0-dep on Python <3.11)
    pyproject = root_dir / "pyproject.toml"
    if pyproject.is_file():
        try:
            txt = pyproject.read_text(encoding="utf-8")
            for m in re.finditer(r'["\']([a-zA-Z0-9_\-]+)\s*(?:[><=~!].*)?["\']', txt):
                declared.add(m.group(1).lower().replace("-", "_"))
                declared.add(m.group(1).lower())
        except Exception:
            pass

    # Cargo.toml
    cargo = root_dir / "Cargo.toml"
    if cargo.is_file():
        try:
            txt = cargo.read_text(encoding="utf-8")
            for m in re.finditer(r"^([a-zA-Z0-9_\-]+)\s*=", txt, re.M):
                declared.add(m.group(1).replace("-", "_"))
        except Exception:
            pass

    return declared


def audit_python_file(file_path: Path, root_dir: Path) -> Dict[str, Any]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    violations: List[Dict[str, Any]] = []

    # 1. Check AST validity
    try:
        tree = ast.parse(content, filename=str(file_path))
    except SyntaxError as e:
        return {
            "file": str(file_path),
            "status": "FAIL",
            "violations": [{"type": "SYNTAX_ERROR", "line": e.lineno or 0, "detail": str(e)}],
        }

    stdlib = _get_python_stdlib_modules()
    local_mods = _discover_local_modules(root_dir)
    declared = _discover_declared_dependencies(root_dir)

    # 2. Check imports & empty stubs in AST
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mod_name = None
            if isinstance(node, ast.Import):
                mod_name = node.names[0].name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.level == 0:
                    mod_name = node.module.split(".")[0]

            if mod_name:
                for pat in SLOPSQUAT_PATTERNS:
                    if pat.match(mod_name):
                        violations.append({
                            "type": "SLOPSQUATTING_RISK",
                            "line": node.lineno,
                            "detail": f"Suspected hallucinated package import: '{mod_name}'",
                        })
                norm = mod_name.lower().replace("-", "_")
                if (
                    mod_name not in stdlib
                    and mod_name not in local_mods
                    and norm not in declared
                    and mod_name not in declared
                ):
                    violations.append({
                        "type": "UNDECLARED_OR_PHANTOM_IMPORT",
                        "line": node.lineno,
                        "detail": f"Module '{mod_name}' is not in Python stdlib, local workspace, or declared manifest.",
                    })

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Detect hollow functions that only have `pass` or `...` (unless abstract)
            body = [
                stmt for stmt in node.body
                if not (isinstance(stmt, ast.Expr) and isinstance(getattr(stmt, "value", None), ast.Constant) and isinstance(stmt.value.value, str))
            ]
            if len(body) == 1:
                stmt = body[0]
                is_ellipsis = isinstance(stmt, ast.Expr) and isinstance(getattr(stmt, "value", None), ast.Constant) and stmt.value.value is Ellipsis
                if isinstance(stmt, ast.Pass) or is_ellipsis:
                    has_decorator = any(
                        isinstance(d, ast.Name) and "abstract" in d.id.lower()
                        for d in node.decorator_list
                    )
                    if not has_decorator and not node.name.startswith("_"):
                        violations.append({
                            "type": "HOLLOW_FUNCTION_STUB",
                            "line": node.lineno,
                            "detail": f"Function '{node.name}' contains only a hollow stub (pass/...).",
                        })

    # 3. Check truncation comments
    for idx, line in enumerate(content.splitlines(), start=1):
        for pat in TRUNCATION_MARKERS:
            if pat.search(line):
                violations.append({
                    "type": "LLM_TRUNCATION_MARKER",
                    "line": idx,
                    "detail": f"Lazy LLM truncation placeholder detected: {line.strip()}",
                })

    return {
        "file": str(file_path),
        "status": "PASS" if not violations else "FAIL",
        "violations": violations,
    }


def audit_ts_or_rust_file(file_path: Path, root_dir: Path) -> Dict[str, Any]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    violations: List[Dict[str, Any]] = []
    declared = _discover_declared_dependencies(root_dir)
    node_builtins = {
        "fs", "path", "os", "crypto", "http", "https", "url", "util", "stream",
        "events", "child_process", "worker_threads", "net", "tls", "zlib", "assert",
        "buffer", " electron", "electron",
    }

    for idx, line in enumerate(content.splitlines(), start=1):
        for pat in TRUNCATION_MARKERS:
            if pat.search(line):
                violations.append({
                    "type": "LLM_TRUNCATION_MARKER",
                    "line": idx,
                    "detail": f"Lazy LLM truncation placeholder detected: {line.strip()}",
                })

        if file_path.suffix in (".ts", ".tsx", ".js", ".mjs"):
            m = re.search(r'(?:from|require\()\s*["\']([^"\']+)["\']', line)
            if m:
                pkg = m.group(1)
                if not pkg.startswith(".") and not pkg.startswith("/") and not pkg.startswith("node:"):
                    base_pkg = pkg.split("/")[0] if not pkg.startswith("@") else "/".join(pkg.split("/")[:2])
                    for pat in SLOPSQUAT_PATTERNS:
                        if pat.match(base_pkg):
                            violations.append({
                                "type": "SLOPSQUATTING_RISK",
                                "line": idx,
                                "detail": f"Suspected hallucinated npm package: '{base_pkg}'",
                            })
                    if declared and base_pkg not in declared and base_pkg not in node_builtins:
                        violations.append({
                            "type": "UNDECLARED_OR_PHANTOM_IMPORT",
                            "line": idx,
                            "detail": f"Package '{base_pkg}' is not declared in package.json or Node builtins.",
                        })

    return {
        "file": str(file_path),
        "status": "PASS" if not violations else "FAIL",
        "violations": violations,
    }


def run_existence_gap_audit(target_path: str) -> Dict[str, Any]:
    """Runs the Popperian Existence-Gap Audit on a file or directory."""
    target = Path(target_path).resolve()
    root_dir = target if target.is_dir() else target.parent

    files_to_scan: List[Path] = []
    if target.is_file():
        files_to_scan.append(target)
    elif target.is_dir():
        for ext in ("*.py", "*.ts", "*.tsx", "*.js", "*.rs"):
            for f in target.rglob(ext):
                if "__pycache__" not in f.parts and "node_modules" not in f.parts and ".git" not in f.parts:
                    files_to_scan.append(f)

    results = []
    total_violations = 0
    for f in sorted(files_to_scan):
        # Skip self-scanning the regex signatures inside existence_gate.py
        if f.name == "existence_gate.py":
            continue
        if f.suffix == ".py":
            res = audit_python_file(f, root_dir)
        else:
            res = audit_ts_or_rust_file(f, root_dir)
        results.append(res)
        total_violations += len(res["violations"])

    status = "PASS" if total_violations == 0 else "FAIL"
    return {
        "verdict": status,
        "files_scanned": len(results),
        "total_violations": total_violations,
        "slop_percentage": round((total_violations / max(1, len(results))) * 100.0, 2) if total_violations else 0.0,
        "reports": [r for r in results if r["violations"]],
    }


if __name__ == "__main__":
    target_arg = sys.argv[1] if len(sys.argv) > 1 else "."
    report = run_existence_gap_audit(target_arg)
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["verdict"] == "PASS" else 1)
