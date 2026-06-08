#!/usr/bin/env python3
import sys, struct, ctypes, math
import texture2ddecoder
from PIL import Image
import pytesseract

def lzfse_decode(src, hint):
    lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
    lib.compression_decode_buffer.restype = ctypes.c_size_t
    lib.compression_decode_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
    cap = max(hint*2, 1<<20); dst = ctypes.create_string_buffer(cap)
    n = lib.compression_decode_buffer(dst, cap, src, len(src), None, 0x801)
    return dst.raw[:n]

def decode(path, out):
    d = open(path,"rb").read()
    w = struct.unpack_from("<I", d, 40)[0]; h = struct.unpack_from("<I", d, 44)[0]
    off = min(i for i in (d.find(b"bvx2"), d.find(b"bvxn"), d.find(b"bvx-")) if i>=0)
    raw = lzfse_decode(d[off:], math.ceil(w/4)*math.ceil(h/4)*16)
    bgra = texture2ddecoder.decode_astc(raw, w, h, 4, 4)
    img = Image.frombytes("RGBA", (w,h), bgra, "raw", "BGRA")
    img.save(out)
    txt = pytesseract.image_to_string(img).strip()
    print(f"{out}  {w}x{h}")
    print(f"  OCR chars={len(txt)} | text: {txt[:160]!r}")
    return out

if __name__=="__main__":
    decode(sys.argv[1], sys.argv[2])
