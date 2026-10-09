"""Signature catalogs enumerate exact module declarations; the execution gate decides generic dispatch."""

import gzip
import json
from pathlib import Path

import pytest

from speakeasy.winenv.api import sigdb


def _source(tmp_path: Path, functions: dict, *, phnt: bool = False, filename: str = "sigs"):
    path = tmp_path / f"{filename}.json.gz"
    with gzip.open(path, "wt") as stream:
        json.dump(
            {
                "format": sigdb.SUPPORTED_FORMAT,
                "functions": functions,
                "dll_aliases": {"psapi": "kernel32", "ntoskrnl": "ntdll"},
                "name_prefixes": {"kernel32": ["K32"]},
            },
            stream,
        )
    return (sigdb.PhntSource if phnt else sigdb.Win32MetadataSource)(str(path))


class _LookupOnlySource(sigdb.SignatureSource):
    @property
    def available(self) -> bool:
        return True

    def lookup(self, dll: str, func: str, arch: str) -> sigdb.FuncSig | None:
        return sigdb.FuncSig(func, dll, "v", ())


def test_catalog_lists_only_exact_module_declarations(tmp_path: Path) -> None:
    source = _source(
        tmp_path,
        {
            "Shared": [{"dll": "user32", "ret": "u32"}, {"dll": "kernel32", "ret": "h"}],
            "OtherOnly": [{"dll": "user32"}],
            "K32EnumProcesses": [{"dll": "kernel32"}],
            "OwnPsapi": [{"dll": "PSAPI.DLL"}],
        },
    )
    catalog = list(source.iter_functions("KERNEL32.dll", "x86"))
    assert [sig.name for sig in catalog] == ["K32EnumProcesses", "Shared"]
    assert catalog[1].dll == "kernel32" and catalog[1].ret == "h"
    assert [sig.name for sig in source.iter_functions("psapi.dll", "x86")] == ["OwnPsapi"]
    assert list(source.iter_functions("api-ms-win-core-test-l1-1-0", "x86")) == []
    assert list(source.iter_functions("unknown", "x86")) == []
    reused = source.lookup("psapi", "EnumProcesses", "x86")
    assert reused is not None and reused.name == "K32EnumProcesses"
    assert source.lookup("unknown", "OtherOnly", "x86") is not None


def test_unsupported_and_skipped_declarations_remain_members(tmp_path: Path) -> None:
    source = _source(
        tmp_path,
        {
            "Skipped": [{"dll": "ntdll", "skip": "unsupported ABI", "conv": "vectorcall"}],
            "FloatReturn": [{"dll": "ntdll", "ret": "f64"}],
            "Variadic": [{"dll": "ntdll", "conv": "cdecl", "variadic": True}],
        },
        phnt=True,
    )
    db = sigdb.SignatureDatabase([source])
    catalog = {sig.name: sig for sig in db.iter_functions("NTDLL.DLL", "x64")}
    assert set(catalog) == {"FloatReturn", "Skipped", "Variadic"}
    assert all(sig.source == "phnt" and not sig.supports_emulation(8) for sig in catalog.values())
    assert db.lookup_exact("ntdll", "FloatReturn", "x64") is catalog["FloatReturn"]
    assert list(source.iter_functions("ntoskrnl.sys", "x64")) == []


@pytest.mark.parametrize("arch,code,only", [("x86", "i32", "Only32"), ("x64", "i64", "Only64")])
def test_architecture_selects_exact_declaration(tmp_path: Path, arch: str, code: str, only: str) -> None:
    source = _source(
        tmp_path,
        {
            "Split": [
                {"dll": "other", "ret": "v"},
                {"dll": "D.DLL", "arch": ["arm64"], "ret": "v"},
                {"dll": "d", "arch": ["x64"], "ret": "i64"},
                {"dll": "D.dll", "arch": ["x86"], "ret": "i32"},
                {"dll": "d", "ret": "u64"},
            ],
            "Only64": [{"dll": "d", "arch": ["x64"]}],
            "Only32": [{"dll": "d", "arch": ["x86"]}],
            "NoArchitectures": [{"dll": "d", "arch": []}],
            "ArmOnly": [{"dll": "d", "arch": ["arm64"]}],
            "Unrestricted": [{"dll": "d"}],
        },
    )
    db = sigdb.SignatureDatabase([source])
    for provider in (source, db):
        catalog = {sig.name: sig for sig in provider.iter_functions("d.dll", arch)}
        assert set(catalog) == {only, "Split", "Unrestricted"}
        assert catalog["Split"].ret == code
        assert provider.lookup_exact("d", "Split", arch) is catalog["Split"]
        assert provider.lookup_exact("d", "NoArchitectures", arch) is None
        assert provider.lookup_exact("d", "ArmOnly", arch) is None
    assert source.lookup("d", "NoArchitectures", arch) is None


def test_lookup_exact_rejects_foreign_dlls_aliases_prefixes_and_name_case(tmp_path: Path) -> None:
    source = _source(
        tmp_path,
        {
            "GetTickCount": [{"dll": "kernel32", "ret": "u32"}],
            "K32EnumProcesses": [{"dll": "kernel32"}],
            "Shared": [{"dll": "kernel32", "ret": "h"}, {"dll": "PSAPI.DLL", "ret": "u32"}],
        },
    )
    db = sigdb.SignatureDatabase([source])
    for provider in (source, db):
        assert provider.lookup_exact("unknown_vendor", "GetTickCount", "x86") is None
        assert provider.lookup_exact("psapi", "GetTickCount", "x86") is None
        assert provider.lookup_exact("kernel32", "EnumProcesses", "x86") is None
        assert provider.lookup_exact("kernel32", "gettickcount", "x86") is None
        shared = provider.lookup_exact("PSAPI.dll", "Shared", "x86")
        assert shared is not None and shared.ret == "u32"
        exact = provider.lookup_exact("KERNEL32.DLL", "GetTickCount", "x86")
        assert exact is not None and exact.dll == "kernel32"
        assert provider.lookup_exact("kernel32", "K32EnumProcesses", "x86") is not None
        assert provider.lookup("unknown_vendor", "GetTickCount", "x86") is exact
        assert provider.lookup("psapi", "EnumProcesses", "x86") is not None


def test_source_precedence_applies_to_catalog_and_exact_lookup(tmp_path: Path) -> None:
    wrong_arch = _source(tmp_path, {"Shared": [{"dll": "d", "arch": ["arm64"]}]}, filename="wrong")
    first = _source(
        tmp_path,
        {"Z": [{"dll": "d"}], "Shared": [{"dll": "d", "skip": "unsupported"}]},
        filename="first",
    )
    second = _source(
        tmp_path,
        {"shared": [{"dll": "d"}], "Shared": [{"dll": "d", "ret": "u32"}], "A": [{"dll": "d"}]},
        filename="second",
        phnt=True,
    )
    db = sigdb.SignatureDatabase([wrong_arch, first, second])
    catalog = {sig.name: sig for sig in db.iter_functions("d", "x86")}
    assert set(catalog) == {"A", "Shared", "shared", "Z"}
    assert catalog["Shared"].skip == "unsupported" and catalog["Shared"].source == "win32metadata"
    assert db.lookup_exact("d", "Shared", "x86") is catalog["Shared"]
    db.add_source(second, first=True)
    catalog = {sig.name: sig for sig in db.iter_functions("d", "x86")}
    assert catalog["Shared"].ret == "u32" and catalog["Shared"].source == "phnt"
    assert db.lookup_exact("d", "Shared", "x86") is catalog["Shared"]


def test_sources_without_catalogs_contribute_no_members(tmp_path: Path) -> None:
    custom = _LookupOnlySource()
    assert list(custom.iter_functions("d", "x86")) == []
    assert custom.lookup_exact("D.DLL", "F", "x86") is not None
    assert list(sigdb.SignatureDatabase([custom]).iter_functions("d", "x86")) == []
    assert sigdb.SignatureDatabase([custom]).lookup_exact("D.DLL", "F", "x86") is not None
    assert sigdb.SignatureDatabase([]).lookup_exact("d", "F", "x86") is None
    missing = sigdb.Win32MetadataSource(str(tmp_path / "missing.json.gz"))
    assert list(missing.iter_functions("kernel32", "x86")) == []
    assert missing.lookup_exact("kernel32", "F", "x86") is None


SCALARS = tuple(sigdb.ParamSig("value", code) for code in ("i32:ENUM", "u64", "b", "S", "p:f64", "ps:RESULT"))


@pytest.mark.parametrize(
    "sig,ptr_size,supported",
    [
        (sigdb.FuncSig("Stdcall", "d", "u32:STATUS", SCALARS), 4, True),
        (sigdb.FuncSig("Cdecl", "d", "v", SCALARS, conv=sigdb.CONV_CDECL), 8, True),
        (sigdb.FuncSig("Wide", "d", "u64", ()), 8, True),
        (sigdb.FuncSig("Wide", "d", "u64", ()), 4, False),
        (sigdb.FuncSig("Float", "d", "f64", ()), 8, False),
        (sigdb.FuncSig("Aggregate", "d", "st:RESULT:24", ()), 8, False),
        (sigdb.FuncSig("FloatArg", "d", "u32", (sigdb.ParamSig("value", "f32"),)), 4, False),
        (sigdb.FuncSig("AggregateArg", "d", "u32", (sigdb.ParamSig("value", "st:VALUE:12/24"),)), 8, False),
        (sigdb.FuncSig("Fastcall", "d", "u32", (), conv="fastcall"), 4, False),
        (sigdb.FuncSig("Variadic", "d", "u32", (), conv=sigdb.CONV_CDECL, variadic=True), 4, False),
        (sigdb.FuncSig("Skipped", "d", "u32", (), skip="unsupported"), 8, False),
        (sigdb.FuncSig("OtherArch", "d", "u32", (), arch=("x64",)), 4, False),
    ],
    ids=lambda value: value.name if isinstance(value, sigdb.FuncSig) else None,
)
def test_generic_execution_gate(sig: sigdb.FuncSig, ptr_size: int, supported: bool) -> None:
    assert sig.supports_emulation(ptr_size) is supported
