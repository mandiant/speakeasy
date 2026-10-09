"""Pinned physical kernel32 exports are evidence; they never extend the synthetic export surface."""

import hashlib
import struct
from pathlib import Path

import pefile
import pytest

from speakeasy import Speakeasy
from speakeasy.windows.loaders import ApiModuleLoader, PeLoader, RuntimeModule
from speakeasy.winenv.api.sigdb import get_default_database
from tests.pe_builder import build_pe

CAPA = Path(__file__).parent / "capa-testfiles"


@pytest.fixture(
    params=[
        (32, "kernel32.dll_", "3f94f8630c7603f9da79bf021cb56ac5357502badf6cb12f6ce11e5b2b244153"),
        (64, "kernel32-64.dll_", "7d148e220040de2fae1439fbc0e783ef344dceaea4757611722d8378a4938d0b"),
    ],
    ids=["win7-x86", "win10-x64"],
)
def physical_kernel32(request):
    architecture, filename, digest = request.param
    path = CAPA / filename
    if not path.is_file():
        pytest.skip("pinned capa DLL fixture is unavailable")
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    return architecture, RuntimeModule(PeLoader(data=raw).make_image())


def test_real_forwarder_is_preserved_but_synthetic_surface_is_local(physical_kernel32):
    architecture, real = physical_kernel32
    db = get_default_database()
    if not db.available:
        pytest.skip("bundled signature database not generated")
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


def query_both(se, module, name):
    """Resolve name through GetProcAddress and LdrGetProcedureAddress in the guest."""
    width = se.emu.get_ptr_size()
    encoded = name.encode()
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


def test_uncatalogued_real_export_fails_lookup_until_a_guest_import_binds_it(physical_kernel32, config):
    architecture, real = physical_kernel32
    name = "BaseThreadInitThunk"
    assert real.get_export_by_name(name) is not None
    config["modules"]["functions_always_exist"] = False
    config["timeout"] = 3
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=b"\xc3", arch="x86" if architecture == 32 else "amd64")
        se.run_shellcode(base)
        kernel32 = se.emu.get_mod_by_name("kernel32")
        assert kernel32.get_export_by_name(name) is None
        before_exports = list(kernel32.get_exports())
        assert query_both(se, kernel32, name) == (0, 0xC000007A, 0)  # STATUS_PROCEDURE_NOT_FOUND
        assert kernel32.get_exports() == before_exports
        assert ("kernel32", name) not in se.get_symbols().values()

        raw, iats = build_pe(architecture, text=b"\xc3", imports={"kernel32.dll": [name]})
        # The shellcode container occupies the default x86 PE base and this PE has no relocations.
        pe = pefile.PE(data=raw, fast_load=True)
        pe.OPTIONAL_HEADER.ImageBase = 0x5000000 if architecture == 32 else 0x150000000
        raw = pe.write()
        pe.close()
        guest = se.load_image(PeLoader(data=raw).make_image())
        width = architecture // 8
        address = int.from_bytes(se.mem_read(guest.base + iats["kernel32.dll", name], width), "little")
        assert address and se.emu.get_address_map(address) is not None
        assert kernel32.get_exports() == before_exports
        assert se.get_symbols()[address] == ("kernel32", name)
        parsed = pefile.PE(data=se.mem_read(kernel32.base, kernel32.image_size))
        assert name.encode() not in {export.name for export in parsed.DIRECTORY_ENTRY_EXPORT.symbols}
        assert query_both(se, kernel32, name) == (address, 0, address)
