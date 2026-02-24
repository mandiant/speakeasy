import lzma
import os

import pytest

import speakeasy.winenv.arch as _arch
from speakeasy.windows.loaders import (
    ApiModuleLoader,
    DecoyLoader,
    ExportEntry,
    IdaLoader,
    ImportEntry,
    LoadedImage,
    MemoryRegion,
    PeLoader,
    RuntimeModule,
    ShellcodeLoader,
)


@pytest.fixture(scope="session")
def pe_data():
    fp = os.path.join(os.path.dirname(__file__), "bins", "dll_test_x86.dll.xz")
    with lzma.open(fp) as f:
        return f.read()


# ---------------------------------------------------------------------------
# Data model tests
# ---------------------------------------------------------------------------


def test_memory_region_construction():
    region = MemoryRegion(base=0x1000, data=b"\x90" * 16, name=".text", perms=0x5)
    assert region.base == 0x1000
    assert region.data == b"\x90" * 16
    assert region.name == ".text"
    assert region.perms == 0x5


def test_import_entry_construction():
    entry = ImportEntry(iat_address=0x4000, dll_name="kernel32.dll", func_name="VirtualAlloc")
    assert entry.iat_address == 0x4000
    assert entry.dll_name == "kernel32.dll"
    assert entry.func_name == "VirtualAlloc"


def test_export_entry_construction():
    entry = ExportEntry(name="DllMain", address=0x401000, ordinal=1, execution_mode="intercepted")
    assert entry.name == "DllMain"
    assert entry.address == 0x401000
    assert entry.ordinal == 1
    assert entry.execution_mode == "intercepted"


def test_export_entry_unnamed():
    entry = ExportEntry(name=None, address=0x401000, ordinal=5, execution_mode="passthrough")
    assert entry.name is None


def test_loaded_image_construction():
    image = LoadedImage(
        arch=0x3,
        module_type="exe",
        name="malware",
        emu_path="C:\\malware.exe",
        image_base=0x400000,
        image_size=0x10000,
        regions=[],
        imports=[],
        exports=[],
        default_export_mode="intercepted",
        entry_points=[0x401000],
    )
    assert image.arch == 0x3
    assert image.module_type == "exe"
    assert image.name == "malware"
    assert image.emu_path == "C:\\malware.exe"
    assert image.image_base == 0x400000
    assert image.image_size == 0x10000
    assert image.entry_points == [0x401000]


def test_loaded_image_defaults():
    image = LoadedImage(
        arch=0,
        module_type="dll",
        name="test",
        emu_path="C:\\test.dll",
        image_base=0x10000000,
        image_size=0x1000,
        regions=[],
        imports=[],
        exports=[],
        default_export_mode="intercepted",
        entry_points=[],
    )
    assert image.visible_in_peb is True
    assert image.stack_size == 0x12000
    assert image.tls_callbacks == []
    assert image.tls_directory_va is None
    assert image.loader is None


# ---------------------------------------------------------------------------
# DecoyLoader tests — must PASS (already implemented)
# ---------------------------------------------------------------------------


@pytest.fixture
def decoy_loader():
    return DecoyLoader(
        name="hal",
        base=0x80100000,
        emu_path="C:\\Windows\\System32\\hal.dll",
        image_size=0x8000,
    )


@pytest.fixture
def decoy_image(decoy_loader):
    return decoy_loader.make_image()


def test_decoy_loader_produces_no_regions(decoy_image):
    assert decoy_image.regions == []


def test_decoy_loader_produces_no_exports(decoy_image):
    assert decoy_image.exports == []


def test_decoy_loader_produces_no_imports(decoy_image):
    assert decoy_image.imports == []


def test_decoy_loader_sets_name(decoy_image):
    assert decoy_image.name == "hal"


def test_decoy_loader_sets_base_address(decoy_image):
    assert decoy_image.image_base == 0x80100000


def test_decoy_loader_sets_emu_path(decoy_image):
    assert decoy_image.emu_path == "C:\\Windows\\System32\\hal.dll"


def test_decoy_loader_sets_image_size(decoy_image):
    assert decoy_image.image_size == 0x8000


def test_decoy_loader_module_type(decoy_image):
    assert decoy_image.module_type == "decoy"


def test_decoy_loader_visible_in_peb(decoy_image):
    assert decoy_image.visible_in_peb is True


def test_decoy_loader_reference_set(decoy_loader, decoy_image):
    assert decoy_image.loader is decoy_loader


# ---------------------------------------------------------------------------
# RuntimeModule tests — must PASS (already implemented)
# ---------------------------------------------------------------------------


def _make_image(
    module_type: str = "exe",
    image_base: int = 0x400000,
    image_size: int = 0x10000,
    entry_points: list[int] | None = None,
    exports: list[ExportEntry] | None = None,
    tls_callbacks: list[int] | None = None,
    emu_path: str = "C:\\Windows\\malware.exe",
    visible_in_peb: bool = True,
) -> LoadedImage:
    return LoadedImage(
        arch=0x3,
        module_type=module_type,
        name="malware",
        emu_path=emu_path,
        image_base=image_base,
        image_size=image_size,
        regions=[],
        imports=[],
        exports=exports or [],
        default_export_mode="intercepted",
        entry_points=entry_points or [],
        visible_in_peb=visible_in_peb,
        tls_callbacks=tls_callbacks or [],
    )


def test_runtime_module_is_exe_for_exe_type():
    mod = RuntimeModule(_make_image(module_type="exe"))
    assert mod.is_exe() is True
    assert mod.is_dll() is False
    assert mod.is_driver() is False


def test_runtime_module_is_dll_for_dll_type():
    mod = RuntimeModule(_make_image(module_type="dll"))
    assert mod.is_dll() is True
    assert mod.is_exe() is False
    assert mod.is_driver() is False


def test_runtime_module_is_driver_for_driver_type():
    mod = RuntimeModule(_make_image(module_type="driver"))
    assert mod.is_driver() is True
    assert mod.is_exe() is False
    assert mod.is_dll() is False


def test_runtime_module_get_base():
    mod = RuntimeModule(_make_image(image_base=0x400000))
    assert mod.get_base() == 0x400000


def test_runtime_module_get_image_size():
    mod = RuntimeModule(_make_image(image_size=0x20000))
    assert mod.get_image_size() == 0x20000


def test_runtime_module_get_emu_path():
    mod = RuntimeModule(_make_image(emu_path="C:\\Windows\\malware.exe"))
    assert mod.get_emu_path() == "C:\\Windows\\malware.exe"


def test_runtime_module_get_base_name_extracts_filename():
    mod = RuntimeModule(_make_image(emu_path="C:\\Windows\\System32\\kernel32.dll"))
    assert mod.get_base_name() == "kernel32.dll"


def test_runtime_module_get_base_name_no_directory():
    mod = RuntimeModule(_make_image(emu_path="malware.exe"))
    assert mod.get_base_name() == "malware.exe"


def test_runtime_module_get_exports_returns_list():
    exports = [
        ExportEntry(name="DllMain", address=0x401000, ordinal=1, execution_mode="intercepted"),
        ExportEntry(name="Init", address=0x402000, ordinal=2, execution_mode="intercepted"),
    ]
    mod = RuntimeModule(_make_image(exports=exports))
    assert mod.get_exports() == exports


def test_runtime_module_get_export_by_name_found():
    exports = [
        ExportEntry(name="DllMain", address=0x401000, ordinal=1, execution_mode="intercepted"),
        ExportEntry(name="Init", address=0x402000, ordinal=2, execution_mode="intercepted"),
    ]
    mod = RuntimeModule(_make_image(exports=exports))
    result = mod.get_export_by_name("Init")
    assert result is not None
    assert result.address == 0x402000


def test_runtime_module_get_export_by_name_missing():
    exports = [
        ExportEntry(name="DllMain", address=0x401000, ordinal=1, execution_mode="intercepted"),
    ]
    mod = RuntimeModule(_make_image(exports=exports))
    assert mod.get_export_by_name("DoesNotExist") is None


def test_runtime_module_get_tls_callbacks():
    callbacks = [0x401500, 0x401600]
    mod = RuntimeModule(_make_image(tls_callbacks=callbacks))
    assert mod.get_tls_callbacks() == callbacks


def test_runtime_module_ep_calculated_from_entry_point():
    image_base = 0x400000
    entry_point = 0x401234
    mod = RuntimeModule(_make_image(image_base=image_base, entry_points=[entry_point]))
    assert mod.ep == entry_point - image_base


def test_runtime_module_ep_zero_when_no_entry_points():
    mod = RuntimeModule(_make_image(entry_points=[]))
    assert mod.ep == 0


def test_runtime_module_visible_in_peb_propagated():
    mod = RuntimeModule(_make_image(visible_in_peb=False))
    assert mod.visible_in_peb is False


def test_runtime_module_module_type_propagated():
    mod = RuntimeModule(_make_image(module_type="driver"))
    assert mod.module_type == "driver"


def test_runtime_module_repr_contains_name_and_base():
    mod = RuntimeModule(_make_image(image_base=0x400000))
    r = repr(mod)
    assert "malware" in r
    assert "0x400000" in r


def test_runtime_module_repr_shows_loader_type():
    loader = DecoyLoader(name="hal", base=0x80100000, emu_path="C:\\hal.dll", image_size=0x1000)
    image = loader.make_image()
    mod = RuntimeModule(image)
    assert "DecoyLoader" in repr(mod)


def test_runtime_module_repr_shows_none_when_no_loader():
    mod = RuntimeModule(_make_image())
    assert "None" in repr(mod)


# ---------------------------------------------------------------------------
# PeLoader tests
# ---------------------------------------------------------------------------


def test_pe_loader_make_image_from_path():
    fp = os.path.join(os.path.dirname(__file__), "bins", "dll_test_x86.dll.xz")
    with lzma.open(fp) as f:
        data = f.read()
    loader = PeLoader(data=data)
    image = loader.make_image()
    assert image.arch == _arch.ARCH_X86
    assert image.module_type == "dll"
    assert image.image_base > 0
    assert image.image_size > 0
    assert len(image.regions) == 1
    assert len(image.regions[0].data) > 0


def test_pe_loader_make_image_from_data(pe_data):
    loader = PeLoader(data=pe_data)
    image = loader.make_image()
    assert image.arch == _arch.ARCH_X86
    assert image.module_type == "dll"
    assert image.image_size > 0
    assert len(image.exports) > 0


# ---------------------------------------------------------------------------
# ShellcodeLoader tests — xfail until implemented
# ---------------------------------------------------------------------------


def test_shellcode_loader_make_image():
    loader = ShellcodeLoader(data=b"\x90\x90\xc3", arch=_arch.ARCH_X86)
    image = loader.make_image()
    assert image.module_type == "shellcode"
    assert image.image_base == 0
    assert image.image_size == 3
    assert len(image.regions) == 1
    assert image.imports == []
    assert image.exports == []
    assert image.entry_points == []
    assert image.visible_in_peb is False


# ---------------------------------------------------------------------------
# IdaLoader tests — xfail until implemented
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="not yet implemented", raises=NotImplementedError)
def test_ida_loader_make_image():
    loader = IdaLoader()
    loader.make_image()


# ---------------------------------------------------------------------------
# ApiModuleLoader tests — xfail until implemented
# ---------------------------------------------------------------------------


def test_api_module_loader_make_image():
    class FakeApiHandler:
        def __init__(self):
            self.funcs = {
                "CreateFileW": ("CreateFileW", None, 7, "stdcall", None),
                "CloseHandle": ("CloseHandle", None, 1, "stdcall", None),
            }
            self.data = {}

    loader = ApiModuleLoader(
        name="kernel32",
        api=FakeApiHandler(),
        arch=_arch.ARCH_X86,
        base=0x76000000,
        emu_path="C:\\Windows\\System32\\kernel32.dll",
    )
    image = loader.make_image()
    assert image.module_type == "dll"
    assert image.name == "kernel32"
    assert image.image_base == 0x76000000
    assert len(image.exports) > 0
    assert len(image.regions) == 1
    export_names = [e.name for e in image.exports if e.name]
    assert "CreateFileW" in export_names or "CreateFileWA" in export_names


# ---------------------------------------------------------------------------
# JitPeFile section consistency tests
# ---------------------------------------------------------------------------


@pytest.fixture(params=[_arch.ARCH_X86, _arch.ARCH_AMD64], ids=["x86", "x64"])
def jit_arch(request):
    return request.param


class TestJitPeSectionConsistency:
    """All JIT PE sections must satisfy VirtualAddress + VirtualSize <= SizeOfImage."""

    @staticmethod
    def _assert_sections_within_image(jit):
        from speakeasy.windows.common import JitPeFile

        soi = jit.basepe.OPTIONAL_HEADER.SizeOfImage
        for sect in jit.basepe.sections:
            name = sect.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            end = sect.VirtualAddress + sect.Misc_VirtualSize
            assert end <= soi, (
                f"section {name}: VirtualAddress(0x{sect.VirtualAddress:x}) + "
                f"Misc_VirtualSize(0x{sect.Misc_VirtualSize:x}) = 0x{end:x} > "
                f"SizeOfImage(0x{soi:x})"
            )

    @staticmethod
    def _assert_raw_data_within_file(jit):
        data_len = len(jit.basepe.__data__)
        for sect in jit.basepe.sections:
            name = sect.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            end = sect.PointerToRawData + sect.SizeOfRawData
            assert end <= data_len, (
                f"section {name}: PointerToRawData(0x{sect.PointerToRawData:x}) + "
                f"SizeOfRawData(0x{sect.SizeOfRawData:x}) = 0x{end:x} > "
                f"len(__data__)(0x{data_len:x})"
            )

    def test_small_export_count(self, jit_arch):
        from speakeasy.windows.common import JitPeFile

        jit = JitPeFile(jit_arch, base=0x70000000)
        jit.get_decoy_pe_image("test_small", [f"Func{i}" for i in range(5)])
        self._assert_sections_within_image(jit)
        self._assert_raw_data_within_file(jit)

    def test_large_export_count(self, jit_arch):
        from speakeasy.windows.common import JitPeFile

        jit = JitPeFile(jit_arch, base=0x70000000)
        jit.get_decoy_pe_image("kernel32", [f"Function{i}" for i in range(500)])
        self._assert_sections_within_image(jit)
        self._assert_raw_data_within_file(jit)

    def test_long_export_names(self, jit_arch):
        from speakeasy.windows.common import JitPeFile

        names = [f"VeryLongExportedFunctionName_{i:04d}_Suffix" for i in range(100)]
        jit = JitPeFile(jit_arch, base=0x70000000)
        jit.get_decoy_pe_image("longnames", names)
        self._assert_sections_within_image(jit)
        self._assert_raw_data_within_file(jit)


def test_api_module_loader_sections_within_image():
    class FakeApiHandler:
        def __init__(self, count):
            self.funcs = {
                f"Func{i}": (f"Func{i}", None, 1, "stdcall", i)
                for i in range(count)
            }
            self.data = {}

    loader = ApiModuleLoader(
        name="kernel32",
        api=FakeApiHandler(200),
        arch=_arch.ARCH_X86,
        base=0x76000000,
        emu_path="C:\\Windows\\System32\\kernel32.dll",
    )
    image = loader.make_image()
    for sect in image.sections:
        end = sect.virtual_address + sect.virtual_size
        assert end <= image.image_size, (
            f"section {sect.name}: virtual_address(0x{sect.virtual_address:x}) + "
            f"virtual_size(0x{sect.virtual_size:x}) = 0x{end:x} > "
            f"image_size(0x{image.image_size:x})"
        )
