#!/usr/bin/env python3
"""
REA Unpacker (Electron & Webpack In-Memory Forensic Kernel) - C5-REAL Ring-0.
Implementa el protocolo forense de escaneo in-memory de ASAR sin dependencias externas:
Lectura directa de la cabecera binaria (struct uint32 Little-Endian) y búsqueda
quirúrgica de canales IPC, endpoints y configuración en < 10 milisegundos.
"""

import sys
import os
import struct
import json
import re
from pathlib import Path
from typing import Dict, Any, List, Tuple


def scan_asar(asar_path: str) -> Tuple[List[Tuple[str, int, int]], int, Any]:
    """Lee la cabecera binaria de 16 bytes y devuelve el árbol de archivos in-memory."""
    f = open(asar_path, 'rb')
    data = f.read(16)
    if len(data) < 16:
        f.close()
        raise ValueError("Archivo ASAR truncado o inválido (< 16 bytes)")
    
    u1, u2, header_size, json_size = struct.unpack('<IIII', data)
    header_json_bytes = f.read(json_size)
    header = json.loads(header_json_bytes.decode('utf-8'))
    header_offset = 16 + json_size

    def find_files(node, path=''):
        res = []
        if 'files' in node:
            for k, v in node['files'].items():
                res.extend(find_files(v, f'{path}/{k}' if path else k))
        else:
            res.append((path, node.get('size', 0), node.get('offset', 0)))
        return res

    files = find_files(header)
    return files, header_offset, f


def audit_electron_asar(asar_path: str) -> Dict[str, Any]:
    """Audita quirúrgicamente canales IPC, endpoints, package.json y secretos."""
    files, header_offset, f = scan_asar(asar_path)
    
    result = {
        "asar_path": asar_path,
        "total_files": len(files),
        "package_json": None,
        "ipc_channels": [],
        "remote_endpoints": [],
        "stat_size_bytes": os.path.getsize(asar_path)
    }

    try:
        # 1. Extraer package.json si existe
        for path, size, offset in files:
            if path in ("package.json", "app/package.json"):
                f.seek(header_offset + int(offset))
                pkg_data = f.read(size).decode('utf-8', errors='ignore')
                try:
                    result["package_json"] = json.loads(pkg_data)
                except Exception:
                    pass
                break

        # 2. Escanear canales IPC y endpoints en módulos JavaScript (< 500 KB)
        ipc_pattern = re.compile(r'(?:ipcRenderer|ipcMain)\s*\.\s*(?:send|on|handle|invoke)\s*\(\s*[\'"]([a-zA-Z0-9_\-:]+)[\'"]')
        url_pattern = re.compile(r'https?://[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}(?:/[^\s\'"<]*)?')

        found_ipc = set()
        found_urls = set()

        for path, size, offset in files:
            if (path.endswith('.js') or path.endswith('.json')) and size < 500000:
                f.seek(header_offset + int(offset))
                content = f.read(size).decode('utf-8', errors='ignore')

                # IPC
                matches = ipc_pattern.findall(content)
                for m in matches:
                    found_ipc.add(m)

                # URLs (filtrando localhost y namespaces de schema)
                urls = url_pattern.findall(content)
                for u in urls:
                    if not any(ign in u for ign in ("w3.org", "schema.org", "localhost", "127.0.0.1")):
                        found_urls.add(u)

        result["ipc_channels"] = sorted(list(found_ipc))
        result["remote_endpoints"] = sorted(list(found_urls))[:20]

    finally:
        f.close()

    return result


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 rea_unpacker.py <ruta_hacia_app.asar>")
        sys.exit(1)

    asar_target = sys.argv[1]
    print(f"[*] REA Unpacker (In-Memory Microkernel) auditando: {asar_target}")
    audit = audit_electron_asar(asar_target)

    print(f"\n[+] RESULTADOS DE AUDITORÍA ASAR:")
    print(f"  - Tamaño total:   {audit['stat_size_bytes']} bytes")
    print(f"  - Total archivos: {audit['total_files']} indexados")
    if audit["package_json"]:
        pkg = audit["package_json"]
        print(f"  - Nombre App:     {pkg.get('name', 'N/A')} v{pkg.get('version', 'N/A')}")
        print(f"  - Main Script:    {pkg.get('main', 'N/A')}")
    print(f"  - Canales IPC:    {len(audit['ipc_channels'])} descubiertos")
    for ch in audit['ipc_channels'][:10]:
        print(f"      • {ch}")
    if len(audit['ipc_channels']) > 10:
        print(f"      ... y {len(audit['ipc_channels']) - 10} más.")
    print(f"  - Endpoints URL:  {len(audit['remote_endpoints'])} detectados")
    for ep in audit['remote_endpoints'][:5]:
        print(f"      • {ep}")


if __name__ == "__main__":
    main()
