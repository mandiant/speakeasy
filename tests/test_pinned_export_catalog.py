"""Pinned physical exports are evidence, not additions to a declaration profile."""

import hashlib
import struct
from pathlib import Path
from types import SimpleNamespace

import pefile
import pytest

from speakeasy import Speakeasy
from speakeasy.windows.loaders import ApiModuleLoader, PeLoader, RuntimeModule
from speakeasy.winenv.api.api import ApiHandler
from speakeasy.winenv.api.sigdb import get_default_database
from speakeasy.winenv.api.usermode.kernel32 import Kernel32
from tests.review_pebuild import build_pe

CAPA = Path(__file__).parent / "capa-testfiles"


@pytest.fixture(
    params=[
        (32, "kernel32.dll_", "3f94f8630c7603f9da79bf021cb56ac5357502badf6cb12f6ce11e5b2b244153", 0x4CE7BAF9),
        (64, "kernel32-64.dll_", "7d148e220040de2fae1439fbc0e783ef344dceaea4757611722d8378a4938d0b", 0x5F488A51),
    ],
    ids=["win7-x86", "win10-x64"],
)
def physical_kernel32(request):
    architecture, filename, digest, timestamp = request.param
    path = CAPA / filename
    if not path.is_file():
        pytest.skip("pinned capa DLL fixture is unavailable")
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    pe = pefile.PE(data=raw, fast_load=True)
    assert pe.FILE_HEADER.TimeDateStamp == timestamp
    pe.close()
    return architecture, RuntimeModule(PeLoader(data=raw).make_image())


def database():
    db = get_default_database()
    if not db.available:
        pytest.skip("bundled signature database not generated")
    return db


def test_real_export_absence_is_not_fabricated_into_signature_profile(physical_kernel32):
    architecture, real = physical_kernel32
    db = database()
    arch = "x86" if architecture == 32 else "x64"
    # Collect decorated declarations without a kernel32 constructor, guest
    # allocation or execution engine. Use the actual export inventory builder.
    handler = Kernel32.__new__(Kernel32)
    ApiHandler.__init__(handler, SimpleNamespace(get_arch=lambda: architecture))
    image = ApiModuleLoader(
        name="kernel32",
        arch=architecture,
        base=0x70000000,
        emu_path=r"C:\Windows\system32\kernel32.dll",
        api=handler,
        signature_db=db,
    ).make_image()
    generated = RuntimeModule(image)
    for name in ("BaseThreadInitThunk", "RtlFillMemory"):
        assert real.get_export_by_name(name) is not None
        assert db.lookup_exact("kernel32", name, arch) is None
        assert generated.get_export_by_name(name) is None
    assert generated.get_export_by_name("GetTickCount") is not None


def test_real_rtl_forwarder_is_preserved_but_synthetic_surface_is_local(physical_kernel32):
    architecture, real = physical_kernel32
    db = database()
    native = real.get_export_by_name("AcquireSRWLockExclusive")
    assert native.forwarder == "NTDLL.RtlAcquireSRWLockExclusive"
    generated = RuntimeModule(
        ApiModuleLoader(
            name="kernel32",
            arch=architecture,
            base=0x70000000,
            emu_path=r"C:\Windows\system32\kernel32.dll",
            signature_db=db,
        ).make_image()
    )
    facade = generated.get_export_by_name("AcquireSRWLockExclusive")
    assert facade is not None and facade.forwarder is None
    assert generated.base <= facade.address < generated.base + generated.image_size
    arch = "x86" if architecture == 32 else "x64"
    assert db.lookup_exact("ntdll", "RtlAcquireSRWLockExclusive", arch) is not None


def query_both(se, module, name):
    """Execute both public Windows lookup APIs through se.call."""
    width = se.emu.get_ptr_size()
    encoded = name.encode()
    # Low pointers are ordinal inputs to GetProcAddress, not name pointers.
    text = se.mem_alloc(0x1000, base=0x20000000)
    se.mem_write(text, encoded + b"\0")
    se.call(se.emu.get_proc("kernel32", "GetProcAddress"), params=[module.base, text])
    assert se.get_report().entry_points[-1].error is None
    win32 = se.reg_read("rax" if width == 8 else "eax")
    ansi = struct.pack("<HH", len(encoded), len(encoded) + 1)
    ansi += (b"\0" * 4 if width == 8 else b"") + text.to_bytes(width, "little")
    descriptor = se.mem_alloc(len(ansi))
    se.mem_write(descriptor, ansi)
    output = se.mem_alloc(width)
    se.mem_write(output, b"\0" * width)
    se.call(se.emu.get_proc("ntdll", "LdrGetProcedureAddress"), params=[module.base, descriptor, 0, output])
    assert se.get_report().entry_points[-1].error is None
    status = se.reg_read("eax")
    native = int.from_bytes(se.mem_read(output, width), "little")
    return win32, status, native


@pytest.mark.parametrize("name", ["BaseThreadInitThunk", "RtlFillMemory"])
def test_public_query_then_explicit_import_of_uncatalogued_real_export(physical_kernel32, name, config):
    architecture, real = physical_kernel32
    assert real.get_export_by_name(name) is not None
    config["modules"]["functions_always_exist"] = False
    config["timeout"] = 3
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=b"\xc3", arch="x86" if architecture == 32 else "amd64")
        se.run_shellcode(base)
        kernel32 = se.emu.get_mod_by_name("kernel32")
        assert kernel32.get_export_by_name(name) is None
        before_exports = list(kernel32.get_exports())
        win32, status, native = query_both(se, kernel32, name)
        assert win32 == native == 0
        assert status == 0xC000007A  # STATUS_PROCEDURE_NOT_FOUND
        assert kernel32.get_exports() == before_exports
        assert not any(value == ("kernel32", name) for value in se.get_symbols().values())

        # Loading a real guest IAT is an explicit request for a dynamic binding,
        # independently of the strict query result and without claiming a
        # physical Windows export or an executable ABI for this missing name.
        raw, iats = build_pe(architecture, text=b"\xc3", imports={"kernel32.dll": [name]})
        # The shellcode container already occupies the ordinary x86 PE base.
        # This fixture has no absolute code operands, so choose its preferred
        # base before parsing rather than asking to relocate an unrelocatable PE.
        pe = pefile.PE(data=raw, fast_load=True)
        pe.OPTIONAL_HEADER.ImageBase = 0x5000000 if architecture == 32 else 0x150000000
        raw = pe.write()
        pe.close()
        # load_module starts a fresh emulator; public load_image adds this PE
        # to the existing session whose strict queries were just exercised.
        guest = se.load_image(PeLoader(data=raw).make_image())
        width = architecture // 8
        slot = guest.base + iats["kernel32.dll", name]
        address = int.from_bytes(se.mem_read(slot, width), "little")
        assert address and se.emu.get_address_map(address) is not None
        entry = se.emu.api_registry.entries[address]
        assert entry.export.visibility == "dynamic"
        assert kernel32.get_exports() == before_exports
        assert kernel32.get_export_by_name(name) is None
        assert se.get_symbols()[address] == ("kernel32", name)
        assert entry.trap not in se.get_symbols()
        parsed = pefile.PE(data=se.mem_read(kernel32.base, kernel32.image_size))
        assert name.encode() not in {export.name for export in parsed.DIRECTORY_ENTRY_EXPORT.symbols}
        assert query_both(se, kernel32, name) == (address, 0, address)
