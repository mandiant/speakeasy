"""Minimal PE32/PE32+ file builder with import tables and no relocations."""

import struct


def build_pe(
    arch=32,
    *,
    text=b"",
    data=b"",
    imports=None,
    nxcompat=False,
    extra_dirs=None,
):
    """Return file bytes and {(DLL, function): IAT RVA}, with no relocations."""
    assert arch in (32, 64)
    is64 = arch == 64
    width = arch // 8
    base = 0x140000000 if is64 else 0x400000
    import_rva = 0x3000
    iat_map = {}
    idata = bytearray()
    import_size = 0
    if imports:
        descriptors = list(imports.items())
        import_size = 20 * (len(descriptors) + 1)
        offset = import_size
        layout = []
        for dll, names in descriptors:
            lookup = offset
            offset += width * (len(names) + 1)
            iat = offset
            offset += width * (len(names) + 1)
            layout.append((dll, names, lookup, iat))
        blobs = []
        hint_names = {}
        dll_names = {}
        for dll, names, _, _ in layout:
            for name in names:
                blob = b"\0\0" + name.encode("ascii") + b"\0"
                blob += b"\0" * (len(blob) & 1)
                hint_names[dll, name] = offset
                blobs.append((offset, blob))
                offset += len(blob)
            blob = dll.encode("latin-1") + b"\0"
            dll_names[dll] = offset
            blobs.append((offset, blob))
            offset += len(blob)
        idata = bytearray(offset)
        for index, (dll, names, lookup, iat) in enumerate(layout):
            struct.pack_into(
                "<5I", idata, index * 20, import_rva + lookup, 0, 0, import_rva + dll_names[dll], import_rva + iat
            )
            for slot, name in enumerate(names):
                value = import_rva + hint_names[dll, name]
                for table in (lookup, iat):
                    struct.pack_into("<Q" if is64 else "<I", idata, table + slot * width, value)
                iat_map[dll, name] = import_rva + iat + slot * width
        for offset, blob in blobs:
            idata[offset : offset + len(blob)] = blob
    if callable(text):
        text = text(base, iat_map)
    sections = [
        (b".text", 0x1000, bytes(text) or b"\xc3", 0x60000020),
        (b".data", 0x2000, bytes(data) or b"\0", 0xC0000040),
        (b".idata", import_rva, bytes(idata) or b"\0", 0xC0000040),
    ]
    assert all(len(content) <= 0x1000 for _, _, content, _ in sections)
    header = bytearray(0x400)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    header[0x80:0x84] = b"PE\0\0"
    optional_size = 240 if is64 else 224
    characteristics = 0x0003 | (0x20 if is64 else 0x100)
    struct.pack_into("<HHIIIHH", header, 0x84, 0x8664 if is64 else 0x14C, 3, 0, 0, 0, optional_size, characteristics)
    optional = 0x98
    struct.pack_into("<HBBIIIII", header, optional, 0x20B if is64 else 0x10B, 0, 0, 0x1000, 0x2000, 0, 0x1000, 0x1000)
    if is64:
        struct.pack_into("<Q", header, optional + 24, base)
    else:
        struct.pack_into("<II", header, optional + 24, 0x2000, base)
    struct.pack_into("<IIHHHHHH", header, optional + 32, 0x1000, 0x200, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<IIIIHH", header, optional + 52, 0, 0x4000, 0x400, 0, 3, 0x100 if nxcompat else 0)
    struct.pack_into("<QQQQII" if is64 else "<IIIIII", header, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    directories = optional + (112 if is64 else 96)
    if import_size:
        struct.pack_into("<II", header, directories + 8, import_rva, import_size)
    for index, (rva, size) in (extra_dirs or {}).items():
        struct.pack_into("<II", header, directories + index * 8, rva, size)
    body = bytearray()
    raw_offset = 0x400
    for index, (name, rva, content, perms) in enumerate(sections):
        raw_size = (len(content) + 0x1FF) & ~0x1FF
        struct.pack_into(
            "<8sIIIIIIHHI",
            header,
            optional + optional_size + index * 40,
            name,
            len(content),
            rva,
            raw_size,
            raw_offset,
            0,
            0,
            0,
            0,
            perms,
        )
        body += content + b"\0" * (raw_size - len(content))
        raw_offset += raw_size
    return bytes(header + body), iat_map
