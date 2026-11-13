#!/usr/bin/env python3
"""Regression tests for in-memory Electron ASAR forensics."""

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rea_unpacker import audit_electron_asar, scan_asar


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


if __name__ == "__main__":
    unittest.main()
