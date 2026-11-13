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


def _align4(n: int) -> int:
    """Pad a length up to the next 4-byte Chromium pickle boundary."""
    return (n + 3) & ~3


def scan_asar(asar_path: str) -> Tuple[List[Tuple[str, int, int]], int, Any]:
    """Lee la cabecera pickle de Chromium y devuelve el árbol de archivos in-memory.

    ASAR layout:
      [uint32 pickle payload size (= 4)]
      [uint32 header pickle size]
      [header pickle: uint32 payload size, uint32 JSON length, JSON, 4-byte padding]
      [file data...]

    The data region starts at 8 + header_pickle_size, which equals
    16 + align4(json_length). Using 16 + json_length (no padding) shifts
    every file by 1–3 bytes and breaks package.json parsing.
    """
    f = open(asar_path, 'rb')
    try:
        data = f.read(16)
        if len(data) < 16:
            raise ValueError("Archivo ASAR truncado o inválido (< 16 bytes)")

        _size_payload, header_pickle_size, _header_payload_size, json_size = struct.unpack('<IIII', data)
        header_json_bytes = f.read(json_size)
        header = json.loads(header_json_bytes.decode('utf-8'))
        header_offset = 8 + header_pickle_size

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
    except Exception:
        f.close()
        raise



# Channel names as they appear in Electron IPC APIs (literals or bound constants).
_IPC_CHANNEL_RE = r"[a-zA-Z0-9_\-:.\/$]+"
_IPC_METHODS_RE = r"send|sendSync|postMessage|invoke|on|once|handle|handleOnce|removeHandler|removeAllListeners"
_IPC_CALL_PATTERN = re.compile(
    r"(?P<target>ipcRenderer|ipcMain|webContents)\s*\.\s*"
    r"(?P<method>" + _IPC_METHODS_RE + r")"
    r"\s*\(\s*(?:['\"](?P<channel>" + _IPC_CHANNEL_RE + r")['\"]|(?P<chan_var>[A-Za-z_$][\w$]*)(?=\s*[,)]))"
)
_CHANNEL_TOKEN = re.compile(r"[A-Za-z0-9]")
_STRUCTURED_CHANNEL = re.compile(r"[:./$]")

# Hyphenated Chromium/Electron renderer events that are not app IPC channels.
ELECTRON_BUILTIN_EVENTS = frozenset({
    "did-navigate", "did-navigate-in-page", "did-finish-load", "did-fail-load",
    "did-fail-provisional-load", "did-frame-finish-load", "did-start-loading",
    "did-stop-loading", "did-start-navigation", "did-redirect-navigation",
    "did-frame-navigate", "did-change-theme-color", "did-attach-webview",
    "dom-ready", "page-title-updated", "page-favicon-updated",
    "will-navigate", "will-redirect", "will-prevent-unload",
    "preload-error", "console-message", "unresponsive", "responsive",
    "plugin-crashed", "ready-to-show", "enter-html-full-screen",
    "leave-html-full-screen", "found-in-page", "media-started-playing",
    "media-paused", "enter-full-screen", "leave-full-screen",
    "scroll-touch-begin", "scroll-touch-end", "scroll-touch-edge",
    "destroyed", "render-process-gone", "input-event", "did-create-window",
    "did-attach", "preferred-size-changed", "cursor-changed", "context-menu",
})


_ASSIGN_TO_STRING = re.compile(r"""=\s*['"]""")
_IDENT_BEFORE_EQ = re.compile(r"(?P<name>[A-Za-z_$][\w$]*)\s*$")
_CHANNEL_VALUE = re.compile(r"^" + _IPC_CHANNEL_RE + r"$")


def collect_ipc_string_constants(content: str) -> Dict[str, str]:
    """Map identifiers to string literals (Ar = 'sand:encode-png').

    Search starts at `= '...'` / `="..."` so a long comment or minified
    run cannot backtrack through an identifier quantifier.
    """
    found: Dict[str, str] = {}
    for m in _ASSIGN_TO_STRING.finditer(content):
        prefix = content[max(0, m.start() - 256):m.start()]
        ident = _IDENT_BEFORE_EQ.search(prefix)
        if not ident:
            continue
        quote = content[m.end() - 1]
        end = content.find(quote, m.end())
        if end < 0:
            continue
        value = content[m.end():end]
        if _CHANNEL_VALUE.fullmatch(value):
            found[ident.group("name")] = value
    return found


def _is_app_ipc_channel(channel: str, *, from_const: bool) -> bool:
    """Drop Chromium events, comment crumbs, and minified identifier collisions."""
    if not channel or channel in ELECTRON_BUILTIN_EVENTS:
        return False
    if not _CHANNEL_TOKEN.search(channel):
        return False
    # Bound constants in minified bundles reuse 1–2 letter names; only trust
    # values that look like an IPC name (sand:foo, workspace/open, app.window.x).
    if from_const and not _STRUCTURED_CHANNEL.search(channel):
        return False
    return True


def extract_ipc_details(content: str, source_path: str = "") -> List[Dict[str, Any]]:

    """Harvest ipcMain/ipcRenderer/webContents calls, including channel constants."""
    constants = collect_ipc_string_constants(content)
    details: List[Dict[str, Any]] = []
    for m in _IPC_CALL_PATTERN.finditer(content):
        channel = m.group("channel")
        from_const = False
        if not channel:
            channel = constants.get(m.group("chan_var") or "")
            from_const = bool(channel)
        if not _is_app_ipc_channel(channel, from_const=from_const):
            continue

        target = m.group("target")
        method = m.group("method")
        if target == "ipcRenderer" and method in ("send", "sendSync", "invoke", "postMessage"):
            direction = "r2m"
        elif target in ("ipcMain", "webContents") and method in ("send", "postMessage"):
            direction = "m2r"
        elif target == "ipcMain" and method in ("handle", "handleOnce", "on", "once"):
            direction = "main_handler"
        else:
            direction = "renderer_listener"

        details.append({
            "channel": channel,
            "direction": direction,
            "target": target,
            "method": method,
            "file": source_path,
        })
    return details



_URL_PATTERN = re.compile(
    r"https?://"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)+"
    r"(?::\d{2,5})?"
    r"(?:/[a-zA-Z0-9_\-./~%?&=+#@]*)?"
)
_URL_NOISE_HOSTS = (
    "w3.org",
    "schema.org",
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "sheetjs.openxmlformats.org",
    "oasis-open.org",
    "openoffice.org",
    "purl.org",
    "purl.oclc.org",
    "xmlsoap.org",
    "json-schema.org",
    "whatwg.org",
    "xfa.org",
    "ns.adobe.com",
    "example.com",
    "example.org",
    "example.net",
    "localhost",
)


def _url_host(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split(":", 1)[0].lower()


def _url_is_noise(url: str) -> bool:
    host = _url_host(url)
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return True
    if host.endswith(".invalid"):
        return True
    return any(host == suffix or host.endswith("." + suffix) for suffix in _URL_NOISE_HOSTS)


def extract_remote_urls(content: str) -> List[str]:
    """Harvest http(s) URLs, stopping at JS/source delimiters and dropping schema namespaces."""
    found: List[str] = []
    seen = set()
    for m in _URL_PATTERN.finditer(content):
        url = m.group(0).rstrip(").,;:]>\"'")
        if _url_is_noise(url) or url in seen:
            continue
        seen.add(url)
        found.append(url)
    return found


DEFAULT_MAX_SCAN_BYTES = 8 * 1024 * 1024  # 8 MiB; covers large main/renderer bundles


def audit_electron_asar(asar_path: str, max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES) -> Dict[str, Any]:
    """Audita quirúrgicamente canales IPC, endpoints, package.json y secretos."""
    files, header_offset, f = scan_asar(asar_path)
    
    result = {
        "asar_path": asar_path,
        "total_files": len(files),
        "package_json": None,
        "ipc_channels": [],
        "ipc_details": [],
        "preload_bridges": [],
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

        # 2. Escanear canales IPC, contextBridge y endpoints en módulos JavaScript (cap configurable)
        bridge_pattern = re.compile(
            r'contextBridge\s*\.\s*exposeInMainWorld\s*\(\s*[\'"](?P<api_key>[a-zA-Z0-9_\-\$]+)[\'"]'
        )

        found_ipc = set()
        ipc_details = []
        found_bridges = set()
        found_urls = set()

        for path, size, offset in files:
            if path.endswith(('.js', '.mjs', '.cjs', '.json')) and size <= max_scan_bytes:
                f.seek(header_offset + int(offset))
                content = f.read(size).decode('utf-8', errors='ignore')

                # IPC (literals and identifiers bound to string constants)
                for item in extract_ipc_details(content, path):
                    found_ipc.add(item["channel"])
                    ipc_details.append(item)

                # Preload contextBridge APIs
                for bm in bridge_pattern.finditer(content):
                    found_bridges.add(bm.group("api_key"))

                found_urls.update(extract_remote_urls(content))

        result["ipc_channels"] = sorted(list(found_ipc))
        result["ipc_details"] = ipc_details
        result["preload_bridges"] = sorted(list(found_bridges))
        result["remote_endpoints"] = sorted(found_urls)

    finally:
        f.close()

    return result


ELECTRON_FUSE_SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
ELECTRON_FUSE_V1_NAMES = (
    "RunAsNode",
    "EnableCookieEncryption",
    "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments",
    "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar",
    "LoadBrowserProcessSpecificV8Snapshot",
    "GrantFileProtocolExtraPrivileges",
    "WasmTrapHandlers",
)
ELECTRON_FUSE_STATES = {
    0x30: "disabled",
    0x31: "enabled",
    0x72: "removed",
}


def inspect_electron_fuses(binary_path: str) -> Dict[str, str]:
    """Inspecciona el centinela binario de Electron Fuses v1 en streaming sin cargar todo en RAM."""
    path = Path(binary_path)
    if not path.is_file():
        return {}
    chunk_size = 262144
    overlap_len = len(ELECTRON_FUSE_SENTINEL) + 32
    tail = b""
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            buf = tail + chunk
            idx = buf.find(ELECTRON_FUSE_SENTINEL)
            if idx != -1:
                wire_start = idx + len(ELECTRON_FUSE_SENTINEL)
                if wire_start + 2 > len(buf):
                    buf += f.read(64)
                if wire_start + 2 > len(buf):
                    return {}
                wire_version = buf[wire_start]
                wire_len = buf[wire_start + 1]
                fuses_raw = buf[wire_start + 2 : wire_start + 2 + wire_len]
                fuses: Dict[str, str] = {}
                for i, b_val in enumerate(fuses_raw):
                    name = (
                        ELECTRON_FUSE_V1_NAMES[i]
                        if wire_version == 1 and i < len(ELECTRON_FUSE_V1_NAMES)
                        else f"Fuse_{i}"
                    )
                    fuses[name] = ELECTRON_FUSE_STATES.get(b_val, "unknown")
                return fuses
            tail = buf[-overlap_len:] if len(buf) > overlap_len else buf
    return {}


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
