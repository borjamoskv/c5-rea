#!/usr/bin/env python3
"""
REA Decompiler (Native Mach-O & ELF Static Analyzer) - C5-REAL Ring-0.
Extrae funciones, basic blocks, Control Flow Graphs (CFG), llamadas a APIs externas
y referencias cruzadas (xrefs) mediante herramientas nativas de macOS (otool, nm)
emitiendo objetos conformes con el esquema Evidence v2.
"""

import sys
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from evidence_schema import (
    MemoryOffset,
    FunctionEvidence,
    EvidenceEnvelopeV2,
)


def get_symbols(binary_path: str) -> List[Tuple[str, str, str]]:
    """Extrae símbolos globales y locales con sus direcciones usando nm."""
    symbols = []
    try:
        out = subprocess.check_output(
            ["nm", "-n", binary_path],
            stderr=subprocess.DEVNULL,
            text=True
        )
        for line in out.splitlines():
            parts = line.strip().split(" ")
            if len(parts) >= 3:
                addr, sym_type, name = parts[0], parts[1], parts[2]
                if sym_type.lower() in ('t', 's'):
                    symbols.append((addr, sym_type, name))
    except Exception:
        pass
    return symbols


def extract_function_cfg(binary_path: str, max_functions: int = 10) -> List[FunctionEvidence]:
    """Desensambla funciones, calcula nodos CFG y extrae xrefs salientes."""
    evidence_list = []
    
    # Ejecutar otool para obtener el desensamblado con símbolos
    try:
        disasm_raw = subprocess.check_output(
            ["otool", "-tvV", binary_path],
            stderr=subprocess.DEVNULL,
            text=True
        )
    except Exception as e:
        print(f"[-] Error ejecutando otool: {e}")
        return []

    lines = disasm_raw.splitlines()
    current_func: Optional[Dict[str, Any]] = None
    
    func_pattern = re.compile(r'^([a-zA-Z0-9_\-\$]+):$')
    instr_pattern = re.compile(r'^([0-9a-fA-F]+)\s+([a-z0-9\.]+)\s*(.*)$')
    stub_pattern = re.compile(r';\s*symbol stub for:\s*([a-zA-Z0-9_]+)')

    for line in lines:
        line_s = line.strip()
        if not line_s:
            continue

        # Detección de inicio de etiqueta/función
        if match_f := func_pattern.match(line_s):
            name = match_f.group(1)
            if current_func and current_func["instructions"]:
                # Consolidar función previa
                evidence = finalize_function_evidence(current_func)
                evidence_list.append(evidence)
                if len(evidence_list) >= max_functions:
                    break

            current_func = {
                "name": name,
                "start_addr": None,
                "end_addr": None,
                "instructions": [],
                "cfg_nodes": 1,
                "xrefs_out": set(),
            }
            continue

        # Detección de instrucción
        if match_i := instr_pattern.match(line_s):
            addr_str = match_i.group(1)
            opcode = match_i.group(2)
            operands = match_i.group(3)

            if not current_func:
                current_func = {
                    "name": f"sub_{addr_str}",
                    "start_addr": f"0x{addr_str}",
                    "end_addr": None,
                    "instructions": [],
                    "cfg_nodes": 1,
                    "xrefs_out": set(),
                }

            current_func["end_addr"] = f"0x{addr_str}"
            current_func["instructions"].append(f"0x{addr_str}\t{opcode}\t{operands}")

            # CFG basic blocks: branches aumentan nodos de control de flujo
            if opcode.startswith('b') or opcode in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                current_func["cfg_nodes"] += 1

            # Extracción de xrefs salientes
            if stub_m := stub_pattern.search(operands):
                current_func["xrefs_out"].add(stub_m.group(1))
            elif opcode in ('bl', 'blr') and '0x' in operands:
                target = operands.split(' ')[0]
                current_func["xrefs_out"].add(target)

            # Si es un retorno 'ret' o tail call a stub, cerramos la función
            if opcode == 'ret' or (opcode == 'b' and stub_pattern.search(operands)):
                evidence_list.append(finalize_function_evidence(current_func))
                current_func = None
                if len(evidence_list) >= max_functions:
                    break

    return evidence_list


def finalize_function_evidence(func_dict: Dict[str, Any]) -> FunctionEvidence:
    """Convierte el diccionario acumulado en un FunctionEvidence validado."""
    pseudocode = "\n".join(func_dict["instructions"][:50])
    if len(func_dict["instructions"]) > 50:
        pseudocode += f"\n... [{len(func_dict['instructions']) - 50} instrucciones adicionales truncadas]"

    return FunctionEvidence(
        symbol_name=func_dict["name"],
        mangled_name=None,
        memory_location=MemoryOffset(
            start_addr=func_dict["start_addr"] or "0x0",
            end_addr=func_dict["end_addr"],
            section="__TEXT.__text"
        ),
        pseudocode=pseudocode,
        cfg_nodes=func_dict["cfg_nodes"],
        xrefs_in=[],
        xrefs_out=sorted(list(func_dict["xrefs_out"])),
        invariants_verified=["ARM64_CFG_LEAF" if func_dict["cfg_nodes"] == 1 else "ARM64_BRANCH_GRAPH"],
        unknowns=[]
    )


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 rea_decompiler.py <ruta_del_binario> [max_funciones]")
        sys.exit(1)

    binary_path = sys.argv[1]
    max_funcs = int(sys.argv[2]) if len(sys.argv) > 2 else 5

    print(f"[*] REA Decompiler analizando binario nativo: {binary_path}")
    functions = extract_function_cfg(binary_path, max_functions=max_funcs)

    print(f"\n[+] FUNCIONES DESCOMPILADAS Y GRAFOS CFG ({len(functions)}):")
    for f in functions:
        print(f"\n  • Función: {f.symbol_name} @ {f.memory_location.start_addr}")
        print(f"    - Nodos CFG:    {f.cfg_nodes}")
        print(f"    - Xrefs Salida: {', '.join(f.xrefs_out) if f.xrefs_out else 'Ninguna'}")
        print(f"    - Invariantes:  {', '.join(f.invariants_verified)}")
        print(f"    - Primeras 3 instrucciones:")
        for line in f.pseudocode.splitlines()[:3]:
            print(f"        {line}")


if __name__ == "__main__":
    main()
