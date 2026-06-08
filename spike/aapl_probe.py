#!/usr/bin/env python3
"""Reverse-engineer Apple 'AAPL' snapshot container: find payload magic + offsets."""
import sys, struct

MAGICS = {
    b'\xABKTX 11\xBB\r\n\x1A\n': "KTX1",
    b'\xABKTX 20\xBB\r\n\x1A\n': "KTX2",
    b'\x89PNG\r\n\x1a\n': "PNG",
    b'\xFF\xD8\xFF': "JPEG",
    bytes([0x5C,0xA1,0xAB,0x13]): "ASTC(LE)",
    bytes([0x13,0xAB,0xA1,0x5C]): "ASTC(BE)",
    b'AAPL\r\n\x1a\n': "AAPL",
    b'bvx2': "LZFSE/bvx2",
    b'bvxn': "LZFSE/bvxn",
    b'bvx-': "LZFSE(raw)",
}

def probe(path):
    d=open(path,'rb').read()
    print(f"file: ...{path[-60:]}")
    print(f"size: {len(d)}")
    print("first 96 bytes hex:")
    for i in range(0,min(96,len(d)),16):
        chunk=d[i:i+16]
        hexs=' '.join(f'{b:02x}' for b in chunk)
        asc=''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f"  {i:4d}: {hexs:<48} {asc}")
    # interpret some header uint32s (LE) after 8-byte magic
    print("uint32 LE values at offsets 8,12,16,20,24,28,32:")
    for off in (8,12,16,20,24,28,32):
        if off+4<=len(d):
            print(f"  @{off}: {struct.unpack_from('<I',d,off)[0]}")
    # scan for embedded magics
    print("embedded magic scan:")
    for mg,name in MAGICS.items():
        start=0
        hits=[]
        while True:
            idx=d.find(mg,start)
            if idx<0: break
            hits.append(idx); start=idx+1
            if len(hits)>=5: break
        if hits and not (name=="AAPL" and hits==[0]):
            print(f"  {name}: offsets {hits}")

if __name__=="__main__":
    for p in sys.argv[1:]:
        probe(p); print("="*50)
