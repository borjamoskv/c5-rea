#!/usr/bin/env python3
"""
REA Orchestrator (Reverse Engineer Anything Engine) - C5-REAL Sovereign Hub.
Coordina el triage preliminar, la extracción de evidencia y el despacho
hacia los subagentes especializados (rea_triage, rea_decompiler, rea_unpacker).
"""

import sys
import os
import math
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from evidence_schema import (
    BinaryTriageReport,
    EvidenceEnvelopeV2,
    MemoryOffset,
    FunctionEvidence,
    IPCEvidence,
)
from rea_unpacker import audit_electron_asar
from rea_decompiler import extract_function_cfg


def calculate_entropy(file_path: Path) -> float:
    """Calcula la entropía de Shannon (0.0 a 8.0 bits/byte)."""
    if not file_path.is_file():
        return 0.0
    byte_counts = [0] * 256
    total_bytes = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            total_bytes += len(chunk)
            for b in chunk:
                byte_counts[b] += 1
    if total_bytes == 0:
        return 0.0
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total_bytes
            entropy -= p * math.log2(p)
    return entropy


def calculate_sha256(file_path: Path) -> str:
    """Calcula el hash criptográfico SHA-256."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def inspect_mach_o(file_path: Path) -> Dict[str, Any]:
    """Extrae arquitectura, dylibs e imports mediante herramientas nativas de macOS."""
    info = {
        "architecture": "unknown",
        "dylibs": [],
        "symbols_count": 0,
        "is_universal": False,
    }
    # lipo info
    try:
        lipo_out = subprocess.check_output(["lipo", "-info", str(file_path)], stderr=subprocess.DEVNULL, text=True)
        if "Architectures in the fat file:" in lipo_out:
            info["is_universal"] = True
            info["architecture"] = lipo_out.split(":")[-1].strip()
        elif "Non-fat file:" in lipo_out:
            info["architecture"] = lipo_out.split("is architecture:")[-1].strip()
    except Exception:
        pass

    # otool -L (Shared libraries)
    try:
        otool_out = subprocess.check_output(["otool", "-L", str(file_path)], stderr=subprocess.DEVNULL, text=True)
        lines = [line.strip().split(" ")[0] for line in otool_out.splitlines()[1:] if line.strip()]
        info["dylibs"] = lines
    except Exception:
        pass

    # nm -gU (Global defined symbols)
    try:
        nm_out = subprocess.check_output(["nm", "-gU", str(file_path)], stderr=subprocess.DEVNULL, text=True)
        info["symbols_count"] = len(nm_out.splitlines())
    except Exception:
        pass

    return info


def run_triage(target_path: str) -> BinaryTriageReport:
    """Ejecuta la fase 1 (Triage) sobre el binario o paquete objetivo."""
    path = Path(target_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Artefacto no encontrado: {target_path}")

    # Si es un bundle .app, buscar el ejecutable principal
    actual_binary = path
    if path.suffix == ".app":
        macos_dir = path / "Contents" / "MacOS"
        if macos_dir.exists():
            binaries = list(macos_dir.glob("*"))
            if binaries:
                actual_binary = binaries[0]

    entropy = calculate_entropy(actual_binary)
    sha256 = calculate_sha256(actual_binary)
    size_bytes = actual_binary.stat().st_size
    mach_info = inspect_mach_o(actual_binary)

    # Heurística de empaquetador (entropía > 7.2 suele indicar compresión/cifrado UPX)
    is_packed = entropy > 7.3
    packer_type = "High-Entropy (UPX/Encrypted)" if is_packed else None

    return BinaryTriageReport(
        target_path=str(actual_binary),
        sha256=sha256,
        file_size_bytes=size_bytes,
        architecture=mach_info["architecture"],
        entropy_shannon=round(entropy, 4),
        is_packed=is_packed,
        packer_type=packer_type,
        imported_libraries=mach_info["dylibs"],
        exported_symbols_count=mach_info["symbols_count"],
    )


def orchestrate_target(
    target_path: str,
    max_functions: int = 8,
    out_dir: Optional[Path] = None
) -> Tuple[EvidenceEnvelopeV2, Path]:
    """Ejecuta el pipeline forense completo y genera el sobre de evidencia consolidado."""
    triage = run_triage(target_path)
    envelope = EvidenceEnvelopeV2(target=triage)

    # Detección y extracción automática de Electron ASAR si existe
    target_p = Path(target_path).resolve()
    asar_candidate = None
    if target_p.suffix == ".asar":
        asar_candidate = target_p
    elif target_p.suffix == ".app":
        candidate = target_p / "Contents" / "Resources" / "app.asar"
        if candidate.exists():
            asar_candidate = candidate

    if asar_candidate:
        asar_audit = audit_electron_asar(str(asar_candidate))
        details_by_channel: Dict[str, List[Dict[str, Any]]] = {}
        for item in asar_audit.get("ipc_details", []):
            ch = item.get("channel")
            if ch:
                details_by_channel.setdefault(ch, []).append(item)

        for ch in asar_audit.get("ipc_channels", []):
            details = details_by_channel.get(ch, [])
            directions = {d.get("direction") for d in details if d.get("direction")}
            sender_locs = {d.get("file") for d in details if d.get("file") and d.get("direction") in ("r2m", "m2r")}
            handler_locs = {d.get("file") for d in details if d.get("file") and d.get("direction") in ("main_handler", "renderer_listener")}

            if "r2m" in directions and "m2r" in directions:
                direction = "bi_directional"
            elif "r2m" in directions or "main_handler" in directions:
                direction = "r2m"
            elif "m2r" in directions or "renderer_listener" in directions:
                direction = "m2r"
            else:
                direction = "inferred_bi_directional"

            sender_loc = sorted(list(sender_locs))[0] if sender_locs else str(asar_candidate)
            handler_loc = sorted(list(handler_locs))[0] if handler_locs else None

            envelope.ipc_channels.append(
                IPCEvidence(
                    channel=ch,
                    direction=direction,
                    sender_location=sender_loc,
                    handler_location=handler_loc,
                    payload_schema={},
                )
            )

    # Extracción y descompilación estática de funciones nativas
    if Path(triage.target_path).is_file() and max_functions > 0:
        native_funcs = extract_function_cfg(triage.target_path, max_functions=max_functions)
        envelope.native_functions = native_funcs

    evidence_dir = out_dir if out_dir else Path(__file__).parent / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    out_file = evidence_dir / f"evidence_{triage.sha256[:12]}.json"
    out_file.write_text(envelope.model_dump_json(indent=2), encoding="utf-8")

    return envelope, out_file


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 rea_orchestrator.py <ruta_del_binario_o_app> [max_funciones] [out_dir]")
        sys.exit(1)

    target = sys.argv[1]
    max_funcs = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 8
    out_dir = Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else None

    print(f"[*] REA Orchestrator iniciando sobre: {target}")
    envelope, out_file = orchestrate_target(target, max_functions=max_funcs, out_dir=out_dir)
    triage = envelope.target

    print("\n[+] REPORTE DE TRIAGE (Nivel 0):")
    print(f"  - Binario:      {triage.target_path}")
    print(f"  - SHA-256:      {triage.sha256}")
    print(f"  - Tamaño:       {triage.file_size_bytes} bytes")
    print(f"  - Arquitectura: {triage.architecture}")
    print(f"  - Entropía:     {triage.entropy_shannon} bits/byte")
    print(f"  - Empaquetado:  {triage.is_packed} ({triage.packer_type or 'Nativo/Descomprimido'})")
    print(f"  - Dylibs:       {len(triage.imported_libraries)} detectadas")
    print(f"  - Símbolos:     {triage.exported_symbols_count} exportados")
    print(f"\n[+] CANALES IPC ENRIQUECIDOS: {len(envelope.ipc_channels)}")
    print(f"[+] FUNCIONES NATIVAS (CFG):  {len(envelope.native_functions)}")
    print(f"[+] Dossier de Evidencia v2 consolidado en: {out_file}")


if __name__ == "__main__":
    main()
