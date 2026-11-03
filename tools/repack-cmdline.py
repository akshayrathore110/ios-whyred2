#!/usr/bin/env python3
"""Rebuild a shim boot.img with a different XNU command line.

The shim ignores the Android boot.img command line and passes the line stored
in the appended SWEETXNU payload instead (offset 0x48, 608 bytes). This tool
patches that payload, recompresses the kernel and rewrites the boot image with
the original header fields, so the result stays bootable.

    tools/repack-cmdline.py --image shim-boot.img --out shim-boot-safe.img \
        --cmdline "debug=0x14e serial=3 disable_kprintf_output=1 \
                   sweetfb_stayon=1 sweetfb_hz=60 sweetfb_native=1 \
                   sweetfbtest=1 sweetlog=0 emmcrw=0 rd=md0 -v keepsyms=1 whyred"

Use this to make a diagnostic image that cannot write to eMMC: rd=md0 keeps
the root off emmcroot0, emmcrw=0 and sweetlog=0 remove the two write paths.
"""

import argparse
import gzip
import zlib
import struct
import sys

PAGE = 4096
MAGIC = b"SWEETXNU"
CMDLINE_OFF = 0x48
CMDLINE_LEN = 608


def parse_boot(data):
    if data[:8] != b"ANDROID!":
        sys.exit("not an Android boot image (no ANDROID! magic)")
    (kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size,
     second_addr, tags_addr, page_size) = struct.unpack_from("<8I", data, 8)
    header_version, _os_version = struct.unpack_from("<2I", data, 40)
    if header_version not in (0, 1, 2):
        sys.exit(f"unsupported boot header version {header_version}")
    return {
        "kernel_size": kernel_size,
        "kernel_addr": kernel_addr,
        "ramdisk_size": ramdisk_size,
        "ramdisk_addr": ramdisk_addr,
        "second_size": second_size,
        "second_addr": second_addr,
        "tags_addr": tags_addr,
        "page_size": page_size,
        "header_version": header_version,
        "name": data[48:64],
        "cmdline": data[64:64 + 512],
    }


def split_kernel(data, hdr):
    start = hdr["page_size"]
    end = start + hdr["kernel_size"]
    field = data[start:end]
    # The kernel field is a gzip member followed by the appended DTB. A plain
    # gzip.GzipFile would try to parse the DTB as a second member; decompressobj
    # stops after the first and hands back the rest in unused_data.
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    image = d.decompress(field) + d.flush()
    if not d.eof:
        sys.exit("kernel gzip member is truncated")
    return image, d.unused_data


def payload_offset(buf):
    off = buf.rfind(MAGIC)
    if off < 0:
        sys.exit("no SWEETXNU payload found")
    if off + CMDLINE_OFF + CMDLINE_LEN > len(buf):
        sys.exit("payload is truncated")
    return off


def pad(blob, page):
    rem = len(blob) % page
    return blob if rem == 0 else blob + b"\0" * (page - rem)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cmdline", required=True)
    args = ap.parse_args()

    data = open(args.image, "rb").read()
    hdr = parse_boot(data)
    image, trailer = split_kernel(data, hdr)

    line = args.cmdline.encode()
    if len(line) >= CMDLINE_LEN:
        sys.exit(f"command line too long ({len(line)} >= {CMDLINE_LEN})")
    off = payload_offset(image)
    patched = bytearray(image)
    patched[off + CMDLINE_OFF:off + CMDLINE_OFF + CMDLINE_LEN] = (
        line + b"\0" * (CMDLINE_LEN - len(line)))

    kernel = gzip.compress(bytes(patched), compresslevel=9, mtime=0) + trailer
    if len(kernel) > hdr["kernel_size"]:
        # Recompressing from a different zlib build can add a few percent.
        # The header carries the new size, so the only limit is the partition
        # (recovery is 64 MiB); grow instead of failing.
        print(f"note: kernel field grew {hdr['kernel_size']} -> {len(kernel)} "
              "bytes", file=sys.stderr)

    out = bytearray()
    out += b"ANDROID!"
    out += struct.pack("<8I", len(kernel), hdr["kernel_addr"], 0,
                       hdr["ramdisk_addr"], 0, hdr["second_addr"],
                    hdr["tags_addr"], hdr["page_size"])
    out += struct.pack("<2I", hdr["header_version"], 0)
    out += hdr["name"]
    out += args.cmdline.encode()[:511].ljust(512, b"\0")
    out += b"\0" * 32  # id
    out += b"\0" * 1024  # extra cmdline space (v1/v2)
    out = pad(bytes(out), hdr["page_size"])
    out += kernel
    out = pad(bytes(out), hdr["page_size"])

    open(args.out, "wb").write(out)
    print(f"wrote {args.out} ({len(out)} bytes), kernel field "
          f"{len(kernel)}/{hdr['kernel_size']} bytes")
    print(f"xnu command line: {args.cmdline}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
