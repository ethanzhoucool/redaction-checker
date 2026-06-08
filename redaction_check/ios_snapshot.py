"""iOS app-switcher snapshot harvesting + decoding.

On iOS the OS persists the app-switcher card to disk as an Apple 'AAPL' container
(misleadingly given a .ktx extension):

    AAPL header  ->  LZFSE-compressed payload  ->  raw ASTC 4x4 texture

This module locates the snapshot(s) for a bundle id inside a Simulator container,
decodes them to a Pillow image, and exposes the compressed-size signal (a blank /
redacted snapshot LZFSE-crushes to a few KB; a real leak is much larger).

No external binaries: LZFSE via macOS libcompression (ctypes), ASTC via texture2ddecoder.
"""
from __future__ import annotations

import ctypes
import math
import os
import struct
from dataclasses import dataclass
from pathlib import Path

import texture2ddecoder
from PIL import Image

AAPL_MAGIC = b"AAPL\r\n\x1a\n"
COMPRESSION_LZFSE = 0x801
GL_COMPRESSED_RGBA_ASTC_4x4 = 0x93B0

_SIM_ROOT = Path.home() / "Library/Developer/CoreSimulator/Devices"


@dataclass
class Snapshot:
    path: Path
    width: int
    height: int
    internal_format: int
    file_size: int          # bytes on disk (AAPL container, LZFSE-compressed)
    compressed_payload: int  # bytes of the LZFSE blob alone

    @property
    def is_astc_4x4(self) -> bool:
        return self.internal_format == GL_COMPRESSED_RGBA_ASTC_4x4


def _lzfse_decode(src: bytes, hint: int) -> bytes:
    lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
    lib.compression_decode_buffer.restype = ctypes.c_size_t
    lib.compression_decode_buffer.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_int,
    ]
    cap = max(hint * 2, 1 << 20)
    dst = ctypes.create_string_buffer(cap)
    n = lib.compression_decode_buffer(dst, cap, src, len(src), None, COMPRESSION_LZFSE)
    if n == 0:
        raise ValueError("LZFSE decompression failed")
    return dst.raw[:n]


def read_header(path: os.PathLike | str) -> Snapshot:
    """Parse an AAPL container header without decoding pixels."""
    data = Path(path).read_bytes()
    if data[:8] != AAPL_MAGIC:
        raise ValueError(f"not an AAPL snapshot: {path}")
    internal = struct.unpack_from("<I", data, 32)[0]
    w = struct.unpack_from("<I", data, 40)[0]
    h = struct.unpack_from("<I", data, 44)[0]
    off = _lzfse_offset(data)
    return Snapshot(
        path=Path(path), width=w, height=h, internal_format=internal,
        file_size=len(data), compressed_payload=(len(data) - off) if off >= 0 else 0,
    )


def _lzfse_offset(data: bytes) -> int:
    cands = [data.find(m) for m in (b"bvx2", b"bvxn", b"bvx-")]
    cands = [c for c in cands if c >= 0]
    return min(cands) if cands else -1


def decode(path: os.PathLike | str) -> Image.Image:
    """Decode an AAPL .ktx snapshot to an RGBA Pillow image."""
    data = Path(path).read_bytes()
    if data[:8] != AAPL_MAGIC:
        raise ValueError(f"not an AAPL snapshot: {path}")
    w = struct.unpack_from("<I", data, 40)[0]
    h = struct.unpack_from("<I", data, 44)[0]
    off = _lzfse_offset(data)
    if off < 0:
        raise ValueError(f"no LZFSE payload found in {path}")
    expect = math.ceil(w / 4) * math.ceil(h / 4) * 16
    raw = _lzfse_decode(data[off:], expect)
    if len(raw) != expect:
        raise ValueError(f"ASTC size mismatch: got {len(raw)} expected {expect}")
    bgra = texture2ddecoder.decode_astc(raw, w, h, 4, 4)
    return Image.frombytes("RGBA", (w, h), bgra, "raw", "BGRA")


def find_snapshots(bundle_id: str, udid: str | None = None,
                   include_downscaled: bool = False) -> list[Snapshot]:
    """Find app-switcher snapshots for a bundle id, newest first.

    Searches every booted/known Simulator device (or just `udid` if given).
    Snapshots live at <container>/Library/SplashBoard/Snapshots/<scene-with-bundle-id>/.
    """
    roots = [_SIM_ROOT / udid] if udid else _list_device_roots()
    found: list[Snapshot] = []
    for dev in roots:
        snap_dirs = dev.glob("data/Containers/Data/Application/*/Library/SplashBoard/Snapshots")
        for sd in snap_dirs:
            for ktx in sd.rglob("*.ktx"):
                if not include_downscaled and "downscaled" in ktx.parts:
                    continue
                if bundle_id not in str(ktx):
                    continue
                try:
                    found.append(read_header(ktx))
                except ValueError:
                    continue
    found.sort(key=lambda s: s.path.stat().st_mtime, reverse=True)
    return found


def _list_device_roots() -> list[Path]:
    if not _SIM_ROOT.exists():
        return []
    return [p for p in _SIM_ROOT.iterdir() if p.is_dir()]
