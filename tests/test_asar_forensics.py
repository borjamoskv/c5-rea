#!/usr/bin/env python3
"""Regression tests for in-memory Electron ASAR forensics."""

import io
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rea_unpacker import DEFAULT_MAX_SCAN_BYTES, audit_electron_asar, extract_ipc_details, scan_asar


def _align4(n: int) -> int:
    return (n + 3) & ~3


def write_asar(path: Path, files: dict, *, pad_header_mod: int = None) -> int:
    """Write a Chromium-pickle ASAR. Returns the JSON header length.

    If pad_header_mod is set (0-3), a dummy key is added so json_len % 4 equals it.
    File offsets follow header insertion order and include 4-byte string padding.
    """
    files = dict(files)
    if pad_header_mod is not None:
        # Provisional header to measure length, then pad.
        def header_len(extra=None):
            tree = _file_tree(files, extra=extra)
            return len(json.dumps(tree, separators=(",", ":")).encode("utf-8"))

        extra = None
        if header_len() % 4 != pad_header_mod:
            for n in range(0, 8):
                candidate = {"_pad": "x" * n}
                if header_len(candidate) % 4 == pad_header_mod:
                    extra = candidate
                    break
            else:
                raise AssertionError("Could not nudge header length to requested alignment")
        else:
            extra = None
    else:
        extra = None

    tree = _file_tree(files, extra=extra)
    header_bytes = json.dumps(tree, separators=(",", ":")).encode("utf-8")
    json_size = len(header_bytes)
    aligned = _align4(json_size)
    header_payload_size = 4 + aligned
    header_pickle_size = 4 + header_payload_size

    with path.open("wb") as f:
        f.write(struct.pack("<I", 4))
        f.write(struct.pack("<I", header_pickle_size))
        f.write(struct.pack("<I", header_payload_size))
        f.write(struct.pack("<I", json_size))
        f.write(header_bytes)
        f.write(b"\x00" * (aligned - json_size))
        for blob in files.values():
            f.write(blob)
    return json_size


def _file_tree(files: dict, extra=None) -> dict:
    offset = 0
    entries = {}
    for name, blob in files.items():
        entries[name] = {"size": len(blob), "offset": str(offset)}
        offset += len(blob)
    tree = {"files": entries}
    if extra:
        tree.update(extra)
    return tree


class AsarOffsetTests(unittest.TestCase):
    def test_package_json_parses_when_header_needs_3_byte_padding(self):
        """A header whose JSON length is 1 mod 4 used to shift every file by 3 bytes."""
        package = {
            "name": "offset-fixture",
            "version": "1.2.3",
            "main": "index.js",
        }
        package_bytes = json.dumps(package, separators=(",", ":")).encode("utf-8")
        index_js = b"console.log('ok');\n"

        with tempfile.TemporaryDirectory() as tmp_dir:
            asar_file = Path(tmp_dir) / "app.asar"
            json_size = write_asar(
                asar_file,
                {"package.json": package_bytes, "index.js": index_js},
                pad_header_mod=1,
            )
            self.assertEqual(json_size % 4, 1)

            files, header_offset, fh = scan_asar(str(asar_file))
            try:
                self.assertEqual(header_offset, 16 + _align4(json_size))
                self.assertEqual(header_offset, 8 + struct.unpack_from("<I", asar_file.read_bytes(), 4)[0])
                self.assertNotEqual(header_offset, 16 + json_size)
            finally:
                fh.close()

            audit = audit_electron_asar(str(asar_file))
            self.assertEqual(audit["total_files"], 2)
            self.assertEqual(audit["package_json"], package)

            # Raw bytes at the computed offset must be exact, not shifted into padding.
            data_start = header_offset
            raw = asar_file.read_bytes()
            self.assertEqual(raw[data_start:data_start + len(package_bytes)], package_bytes)
            self.assertEqual(
                raw[data_start + len(package_bytes):data_start + len(package_bytes) + len(index_js)],
                index_js,
            )


class ScanSizeCapTests(unittest.TestCase):
    def test_default_cap_includes_large_main_bundles(self):
        """Files just over the old 500 KiB cap must be scanned by default."""
        padding = b"/* " + b"x" * 520_000 + b" */\n"
        body = padding + b"ipcRenderer.invoke('big:main-channel');\n"
        self.assertGreater(len(body), 500_000)
        self.assertLess(len(body), DEFAULT_MAX_SCAN_BYTES)

        with tempfile.TemporaryDirectory() as tmp_dir:
            asar_file = Path(tmp_dir) / "app.asar"
            write_asar(asar_file, {"main-app.cjs": body})
            audit = audit_electron_asar(str(asar_file))
            self.assertIn("big:main-channel", audit["ipc_channels"])

            skipped = audit_electron_asar(str(asar_file), max_scan_bytes=500_000)
            self.assertNotIn("big:main-channel", skipped["ipc_channels"])


class IpcConstantResolutionTests(unittest.TestCase):
    def test_extract_ipc_follows_assigned_string_constants(self):
        """Minified bindings like Ar='sand:encode-png' must resolve at ipcRenderer.on(Ar, ...)."""
        sample = (
            "var Ar='sand:encode-png',hr='sand:main-edge-served',"
            "Tr='sand:network-online',br='sand:renderer-alive',"
            "Or='sand:renderer-boot-gate-landed',Nr='sand:renderer-boot-gate-opened';\n"
            "ipcRenderer.sendSync(\"sand:boot-snapshot-sync\");\n"
            "ipcRenderer.on(\"sand:coordinator-port\", () => {});\n"
            "ipcRenderer.on(Ar, () => {});\n"
            "ipcRenderer.once(hr, cb);\n"
            "ipcRenderer.send(Tr);\n"
            "ipcRenderer.send(br);\n"
            "ipcRenderer.send(Or);\n"
            "ipcRenderer.send(Nr);\n"
            "ipcRenderer.on(unknownChannel, () => {});\n"
            "webContents.on('dom-ready', () => {});\n"
        )
        channels = {item["channel"] for item in extract_ipc_details(sample, "preload.cjs")}
        expected = {
            "sand:encode-png",
            "sand:main-edge-served",
            "sand:network-online",
            "sand:renderer-alive",
            "sand:renderer-boot-gate-landed",
            "sand:renderer-boot-gate-opened",
            "sand:boot-snapshot-sync",
            "sand:coordinator-port",
        }
        self.assertEqual(channels, expected)
        self.assertNotIn("dom-ready", channels)
        self.assertNotIn("unknownChannel", channels)

    def test_extract_ipc_ignores_method_calls_and_plain_minified_consts(self):
        """Do not treat t.createKey(...) or reused minified names as channels."""
        sample = (
            "var t='info',e='//',j='away';\n"
            "on.ipcMain.on(t.createKey('start'), handler);\n"
            "n.webContents.send(e, t);\n"
            "$.webContents.send(j, O);\n"
            "a.webContents.on('destroyed', s);\n"
            "a.webContents.on('render-process-gone', s);\n"
            "ipcMain.on('info', handler);\n"
        )
        channels = {item["channel"] for item in extract_ipc_details(sample)}
        self.assertEqual(channels, {"info"})

    def test_asar_audit_resolves_ipc_channel_constants(self):
        preload = (
            b"var Ar='sand:encode-png';\n"
            b"ipcRenderer.on(Ar, () => {});\n"
            b"ipcMain.handle('workspace/open', async () => {});\n"
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            asar_file = Path(tmp_dir) / "app.asar"
            write_asar(asar_file, {"preload.cjs": preload})
            audit = audit_electron_asar(str(asar_file))
            self.assertIn("sand:encode-png", audit["ipc_channels"])
            self.assertIn("workspace/open", audit["ipc_channels"])


class UnpackEnvelopeTests(unittest.TestCase):
    def test_unpack_cli_writes_evidence_envelope(self):
        """unpack must seal an EvidenceEnvelopeV2, not only print a summary."""
        package_bytes = b'{"name":"seal-fixture","version":"0.0.1"}'
        preload = (
            b"const { contextBridge, ipcRenderer } = require('electron');\n"
            b"contextBridge.exposeInMainWorld('api', {\n"
            b"  ping: () => ipcRenderer.invoke('seal:ping'),\n"
            b"});\n"
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            asar_file = tmp / "app.asar"
            out_dir = tmp / "evidence"
            write_asar(asar_file, {"package.json": package_bytes, "preload.cjs": preload})

            import c5_rea_cli
            argv = ["c5-rea", "unpack", str(asar_file), "--out", str(out_dir)]
            buf = io.StringIO()
            with mock.patch.object(sys, "argv", argv), mock.patch("sys.stdout", buf):
                c5_rea_cli.main()

            envelopes = list(out_dir.glob("evidence_*.json"))
            self.assertEqual(len(envelopes), 1, buf.getvalue())
            data = json.loads(envelopes[0].read_text(encoding="utf-8"))
            self.assertIn("target", data)
            self.assertIn("ipc_channels", data)
            channels = [item["channel"] for item in data["ipc_channels"]]
            self.assertIn("seal:ping", channels)
            self.assertIn("Dossier v2", buf.getvalue())
            self.assertIn(str(envelopes[0]), buf.getvalue())


if __name__ == "__main__":
    unittest.main()
