#!/usr/bin/env python3
"""Inspect an Apple app-switcher KTX snapshot to determine its container + pixel format."""
import sys, struct

KTX1_ID = bytes([0xAB,0x4B,0x54,0x58,0x20,0x31,0x31,0xBB,0x0D,0x0A,0x1A,0x0A])
KTX2_ID = bytes([0xAB,0x4B,0x54,0x58,0x20,0x32,0x30,0xBB,0x0D,0x0A,0x1A,0x0A])

# Common glInternalFormat codes we might see
GL_FORMATS = {
    0x93B0: "ASTC_4x4", 0x93B1: "ASTC_5x4", 0x93B2: "ASTC_5x5", 0x93B3: "ASTC_6x5",
    0x93B4: "ASTC_6x6", 0x93B7: "ASTC_8x8", 0x8058: "RGBA8", 0x8C43: "SRGB8_ALPHA8",
    0x881A: "RGBA16F", 0x8051: "RGB8", 0x83F3: "DXT5/BC3",
}
# VkFormat codes (KTX2)
VK_FORMATS = {
    37:"R8G8B8A8_UNORM", 43:"R8G8B8A8_SRGB", 50:"B8G8R8A8_UNORM", 1000054000:"ASTC?",
    157:"ASTC_4x4_UNORM", 158:"ASTC_4x4_SRGB", 23:"R8G8B8_UNORM",
}

def inspect(path):
    with open(path,"rb") as f:
        data=f.read()
    print(f"file: {path}")
    print(f"size: {len(data)} bytes")
    head=data[:12]
    if head==KTX1_ID:
        print("container: KTX1")
        endian=struct.unpack_from("<I",data,12)[0]
        le = endian==0x04030201
        fmt = "<" if le else ">"
        (glType,glTypeSize,glFormat,glInternalFormat,glBaseInternalFormat,
         w,h,depth,arr,faces,levels,kvbytes)=struct.unpack_from(fmt+"12I",data,16)
        print(f"  endian={'LE' if le else 'BE'} glType={glType:#x} glFormat={glFormat:#x}")
        print(f"  glInternalFormat={glInternalFormat:#x} -> {GL_FORMATS.get(glInternalFormat,'UNKNOWN')}")
        print(f"  pixelWidth={w} pixelHeight={h} depth={depth} levels={levels} kvbytes={kvbytes}")
        img_data_off = 64+kvbytes
        if img_data_off+4<=len(data):
            img_size=struct.unpack_from(fmt+"I",data,img_data_off)[0]
            print(f"  level0 imageSize={img_size} (data region={len(data)-img_data_off-4})")
    elif head==KTX2_ID:
        print("container: KTX2")
        (vkFormat,typeSize,w,h,depth,layers,faces,levels,scheme)=struct.unpack_from("<9I",data,12)
        print(f"  vkFormat={vkFormat} -> {VK_FORMATS.get(vkFormat,'UNKNOWN')}")
        print(f"  pixelWidth={w} pixelHeight={h} levels={levels} supercompression={scheme}")
    else:
        print(f"container: UNKNOWN magic={head.hex()}")

if __name__=="__main__":
    for p in sys.argv[1:]:
        inspect(p); print("-"*40)
