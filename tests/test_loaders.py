from pathlib import Path

import pytest

import speakeasy.winenv.arch as _arch
from speakeasy.windows.loaders import (
    ApiModuleLoader,
    DecoyLoader,
    ExportEntry,
    LoadedImage,
    PeLoader,
    RuntimeModule,
    SectionEntry,
    ShellcodeLoader,
)


@pytest.fixture(scope="session")
def pe_data(load_test_bin):
    return load_test_bin("dll_test_x86.dll.xz")


def _make_image(
    module_type: str = "exe",
    image_base: int = 0x400000,
    image_size: int = 0x10000,
    entry_points: list[int] | None = None,
    exports: list[ExportEntry] | None = None,
    sections: list[SectionEntry] | None = None,
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
        sections=sections or [],
    )


def test_decoy_loader_make_image_properties():
    loader = DecoyLoader(
        name="hal",
        base=0x80100000,
        emu_path="C:\\Windows\\System32\\hal.dll",
        image_size=0x8000,
    )
    image = loader.make_image()
    assert image.module_type == "decoy"
    assert image.name == "hal"
    assert image.emu_path == "C:\\Windows\\System32\\hal.dll"
    assert image.image_base == 0x80100000
    assert image.image_size == 0x8000
    assert image.regions == []
    assert image.imports == []
    assert image.exports == []
    assert image.visible_in_peb is True
    assert image.loader is loader


@pytest.mark.parametrize(
    ("module_type", "is_exe", "is_dll", "is_driver"),
    [
        ("exe", True, False, False),
        ("dll", False, True, False),
        ("driver", False, False, True),
    ],
)
def test_runtime_module_type_helpers(module_type, is_exe, is_dll, is_driver):
    mod = RuntimeModule(_make_image(module_type=module_type))
    assert mod.is_exe() is is_exe
    assert mod.is_dll() is is_dll
    assert mod.is_driver() is is_driver


def test_runtime_module_export_lookup_and_base_name():
    exports = [
        ExportEntry(name="DllMain", address=0x401000, ordinal=1, execution_mode="intercepted"),
        ExportEntry(name="Init", address=0x402000, ordinal=2, execution_mode="intercepted"),
    ]
    mod = RuntimeModule(
        _make_image(
            emu_path="C:\\Windows\\System32\\kernel32.dll",
            exports=exports,
        )
    )
    found = mod.get_export_by_name("Init")
    assert mod.get_base_name() == "kernel32.dll"
    assert found is not None
    assert found.address == 0x402000
    assert mod.get_export_by_name("DoesNotExist") is None


def test_runtime_module_uses_entrypoint_and_tls_callbacks_from_image():
    image_base = 0x400000
    mod = RuntimeModule(
        _make_image(
            image_base=image_base,
            entry_points=[0x401234],
            tls_callbacks=[0x401500, 0x401600],
        )
    )
    assert mod.ep == 0x1234
    assert mod.get_tls_callbacks() == [0x401500, 0x401600]


def test_runtime_module_get_section_for_addr():
    sections = [
        SectionEntry(name=".text", virtual_address=0x1000, virtual_size=0x2000, perms=0x5),
        SectionEntry(name=".rdata", virtual_address=0x4000, virtual_size=0x1000, perms=0x1),
    ]
    mod = RuntimeModule(_make_image(image_base=0x400000, sections=sections))
    assert mod.get_section_for_addr(0x401123).name == ".text"
    assert mod.get_section_for_addr(0x404100).name == ".rdata"
    assert mod.get_section_for_addr(0x500000) is None


def test_runtime_module_repr_includes_loader_type():
    loader = DecoyLoader(name="hal", base=0x80100000, emu_path="C:\\hal.dll", image_size=0x1000)
    mod = RuntimeModule(loader.make_image())
    assert "DecoyLoader" in repr(mod)


def test_pe_loader_make_image_from_path(pe_data, tmp_path: Path):
    pe_path = tmp_path / "sample.dll"
    pe_path.write_bytes(pe_data)

    loader = PeLoader(path=str(pe_path))
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
    assert len(image.imports) > 0
    assert len(image.exports) > 0
    assert len(image.sections) > 0


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


@pytest.mark.xfail(reason="not yet implemented", raises=NotImplementedError)
def test_ida_loader_make_image():
    from speakeasy.windows.loaders import IdaLoader

    loader = IdaLoader()
    loader.make_image()


def test_api_module_loader_make_image():
    class FakeApiHandler:
        def __init__(self):
            self.funcs = {
                "CreateFileW": ("CreateFileW", None, 7, "stdcall", None),
                "CloseHandle": ("CloseHandle", None, 1, "stdcall", None),
            }
            self.data = {"GlobalCounter": 0x1234}

    loader = ApiModuleLoader(
        name="kernel32",
        api=FakeApiHandler(),
        arch=_arch.ARCH_X86,
        base=0x76000000,
        emu_path="C:\\Windows\\System32\\kernel32.dll",
    )
    image = loader.make_image()
    export_names = {exp.name for exp in image.exports if exp.name}

    assert image.module_type == "dll"
    assert image.name == "kernel32"
    assert image.image_base == 0x76000000
    assert len(image.exports) > 0
    assert len(image.regions) == 1
    assert "CreateFileW" in export_names or "CreateFileWA" in export_names
    assert "GlobalCounter" in export_names


@pytest.fixture(params=[_arch.ARCH_X86, _arch.ARCH_AMD64], ids=["x86", "x64"])
def jit_arch(request):
    return request.param


def _assert_jit_sections_within_image(jit):
    size_of_image = jit.basepe.OPTIONAL_HEADER.SizeOfImage
    for section in jit.basepe.sections:
        end = section.VirtualAddress + section.Misc_VirtualSize
        assert end <= size_of_image


def _assert_jit_raw_data_within_file(jit):
    data_len = len(jit.basepe.__data__)
    for section in jit.basepe.sections:
        end = section.PointerToRawData + section.SizeOfRawData
        assert end <= data_len


@pytest.mark.parametrize(
    "module_name,export_names",
    [
        ("small", [f"Func{i}" for i in range(5)]),
        ("large", [f"Function{i}" for i in range(500)]),
        ("longnames", [f"VeryLongExportedFunctionName_{i:04d}_Suffix" for i in range(100)]),
    ],
    ids=["small", "large", "long-names"],
)
def test_jit_pe_section_consistency(jit_arch, module_name, export_names):
    from speakeasy.windows.common import JitPeFile

    jit = JitPeFile(jit_arch, base=0x70000000)
    jit.get_decoy_pe_image(module_name, export_names)
    _assert_jit_sections_within_image(jit)
    _assert_jit_raw_data_within_file(jit)


def test_api_module_loader_sections_within_image():
    class FakeApiHandler:
        def __init__(self, count):
            self.funcs = {f"Func{i}": (f"Func{i}", None, 1, "stdcall", i) for i in range(count)}
            self.data = {}

    loader = ApiModuleLoader(
        name="kernel32",
        api=FakeApiHandler(200),
        arch=_arch.ARCH_X86,
        base=0x76000000,
        emu_path="C:\\Windows\\System32\\kernel32.dll",
    )
    image = loader.make_image()

    for section in image.sections:
        end = section.virtual_address + section.virtual_size
        assert end <= image.image_size
