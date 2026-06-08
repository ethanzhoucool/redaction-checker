#!/usr/bin/env python3
"""Decode Apple AAPL snapshot: parse header -> LZFSE decompress -> verify ASTC size.
Writes a .astc file ready for astcenc if decompression checks out."""
import sys, struct, ctypes, math, os

def lzfse_decode(src: bytes, hint: int) -> bytes:
    lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
    COMPRESSION_LZFSE = 0x801
    lib.compression_decode_buffer.restype = ctypes.c_size_t
    lib.compression_decode_buffer.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_int]
    cap = max(hint * 2, 1 << 20)
    dst = ctypes.create_string_buffer(cap)
    n = lib.compression_decode_buffer(dst, cap, src, len(src), None, COMPRESSION_LZFSE)
    return dst.raw[:n]

def parse(path):
    d = open(path, "rb").read()
    assert d[:8] == b"AAPL\r\n\x1a\n", "not an AAPL container"
    internal = struct.unpack_from("<I", d, 32)[0]
    glfmt    = struct.unpack_from("<I", d, 36)[0]
    w        = struct.unpack_from("<I", d, 40)[0]
    h        = struct.unpack_from("<I", d, 44)[0]
    # locate LZFSE frame (bvx2 / bvxn / bvx-)
    off = -1
    for mg in (b"bvx2", b"bvxn", b"bvx-"):
        i = d.find(mg)
        if i >= 0:
            off = i if off < 0 else min(off, i)
    comp = d[off:] if off >= 0 else b""
    print(f"file: ...{path[-48:]}")
    print(f"  internalFormat={internal:#x} glFormat={glfmt:#x} dims={w}x{h}")
    print(f"  fileSize={len(d)} lzfseOffset={off} compSize={len(comp)}")
    bx = by = 4  # ASTC 4x4
    nblocks = math.ceil(w/bx) * math.ceil(h/by)
    expect = nblocks * 16
    raw = lzfse_decode(comp, expect) if comp else b""
    print(f"  decompressed={len(raw)}  expectedASTC(4x4)={expect}  match={len(raw)==expect}")
    if raw and len(raw) == expect:
        astc = bytearray()
        astc += bytes([0x13,0xAB,0xA1,0x5C, bx,by,1])
        astc += struct.pack("<I", w)[:3] + struct.pack("<I", h)[:3] + struct.pack("<I", 1)[:3]
        astc += raw
        out = path + ".astc"
        open(out,"wb").write(astc)
        print(f"  wrote {out} ({len(astc)} bytes) -> astcenc -dl {out} out.png 4x4")
        return out, w, h
    return None, w, h

if __name__ == "__main__":
    for p in sys.argv[1:]:
        parse(p); print("-"*40)
