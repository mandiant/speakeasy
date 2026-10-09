"""Strict declaration catalogs are separate from permissive ABI lookup."""

import gzip
import json
from pathlib import Path

import pytest

from speakeasy.windows.winemu import WindowsEmulator
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


def test_exact_module_membership_without_aliases_or_fallback(tmp_path: Path) -> None:
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
    # Signature reuse remains available, but cannot establish catalog membership.
    reused = source.lookup("psapi", "EnumProcesses", "x86")
    assert reused is not None and reused.name == "K32EnumProcesses"
    assert source.lookup("unknown", "OtherOnly", "x86") is not None


@pytest.mark.parametrize("arch,code,only", [("x86", "i32", "Only32"), ("x64", "i64", "Only64")])
def test_architecture_selects_exact_declaration(tmp_path: Path, arch: str, code: str, only: str) -> None:
    source = _source(
        tmp_path,
        {
            "Split": [
                {"dll": "other", "ret": "v"},
                {"dll": "d", "arch": ["x64"], "ret": "i64"},
                {"dll": "d", "arch": ["x86"], "ret": "i32"},
            ],
            "Only64": [{"dll": "d", "arch": ["x64"]}],
            "Only32": [{"dll": "d", "arch": ["x86"]}],
            "Both": [{"dll": "d", "arch": ["x86", "x64"]}],
            "Unrestricted": [{"dll": "d"}],
        },
    )
    catalog = {sig.name: sig for sig in source.iter_functions("d.dll", arch)}
    assert set(catalog) == {"Both", only, "Split", "Unrestricted"}
    assert catalog["Split"].ret == code
    assert all(sig.supports_arch(arch) for sig in catalog.values())


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
    catalog = list(sigdb.SignatureDatabase([source]).iter_functions("NTDLL.DLL", "x64"))
    assert [sig.name for sig in catalog] == ["FloatReturn", "Skipped", "Variadic"]
    assert catalog[0].ret == "f64"
    assert catalog[1].skip == "unsupported ABI" and catalog[1].conv == "vectorcall"
    assert catalog[2].variadic
    assert all(sig.source == "phnt" for sig in catalog)
    assert list(source.iter_functions("ntoskrnl.sys", "x64")) == []


def test_names_sorted_duplicates_exact_and_signatures_lazy(tmp_path: Path) -> None:
    source = _source(
        tmp_path,
        {
            "zeta": [{"dll": "d"}],
            "alpha": [{"dll": "d"}],
            "Alpha": [{"dll": "d", "ret": "u32"}, {"dll": "d", "ret": "u64"}],
            "Foreign": [{"dll": "other"}],
        },
    )
    iterator = source.iter_functions("d", "x86")
    assert iter(iterator) is iterator
    assert not source._loaded and not source._sig_cache
    first = next(iterator)
    assert first.name == "Alpha" and first.ret == "u32"
    assert set(source._sig_cache) == {("Alpha", 0)}
    catalog = [first, *iterator]
    assert [sig.name for sig in catalog] == ["Alpha", "alpha", "zeta"]
    assert list(source.iter_functions("d", "x86")) == catalog
    assert next(source.iter_functions("d", "x86")) is first
    assert source.lookup("d", "Alpha", "x86") is first
    assert ("Foreign", 0) not in source._sig_cache
    assert ("Alpha", 1) not in source._sig_cache


@pytest.mark.parametrize("foreign_dlls", [1, 128])
def test_catalog_operations_only_touch_requested_dll_after_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, foreign_dlls: int
) -> None:
    functions = {
        f"Foreign{dll}_{name}": [{"dll": f"foreign{dll}", "arch": ["x86", "x64"]}]
        for dll in range(foreign_dlls)
        for name in range(16)
    }
    functions.update(
        {
            "Z": [{"dll": "D.DLL", "arch": ["x86", "x64"]}],
            "A": [
                {"dll": "d", "arch": ["arm64"]},
                {"dll": "d", "arch": ["x86", "x64"]},
                {"dll": "d", "arch": ["x86", "x64"], "ret": "u64"},
            ],
        }
    )
    source = _source(tmp_path, functions)
    assert source.available
    assert not source._sig_cache

    normalized = []
    sorted_sizes = []
    arch_checks = []
    normalize = sigdb.normalize_dll
    sort = sorted

    def count_normalize(dll):
        normalized.append(dll)
        return normalize(dll)

    def count_sort(values):
        values = list(values)
        sorted_sizes.append(len(values))
        return sort(values)

    class CountingArches(list):
        def __contains__(self, arch):
            arch_checks.append(arch)
            return super().__contains__(arch)

    for entries in source._functions.values():
        for entry in entries:
            entry["arch"] = CountingArches(entry["arch"])
    monkeypatch.setattr(sigdb, "normalize_dll", count_normalize)
    monkeypatch.setattr(sigdb, "sorted", count_sort, raising=False)

    for arch in ("x86", "x64", "x86"):
        catalog = list(source.iter_functions("D.DLL", arch))
        assert [sig.name for sig in catalog] == ["A", "Z"]
        assert catalog[0].ret == "p"
    assert list(source.iter_functions("missing.dll", "x86")) == []
    assert normalized == ["D.DLL", "D.DLL", "D.DLL", "missing.dll"]
    assert sorted_sizes == []
    # Check each candidate once, stopping at the first eligible duplicate.
    assert arch_checks == ["x86"] * 3 + ["x64"] * 3 + ["x86"] * 3
    assert set(source._sig_cache) == {("A", 1), ("Z", 0)}


@pytest.mark.parametrize("arch,ret,index", [("x86", "i32", 3), ("x64", "i64", 2), ("arm64", "h", 4)])
def test_index_preserves_normalized_dll_declaration_order(tmp_path: Path, arch: str, ret: str, index: int) -> None:
    source = _source(
        tmp_path,
        {
            "Shared": [
                {"dll": "foreign", "ret": "v"},
                {"dll": "D.DLL", "arch": [], "ret": "v"},
                {"dll": "d", "arch": ["x64"], "ret": "i64", "skip": "unsupported"},
                {"dll": "D.dll", "arch": ["x86"], "ret": "i32"},
                {"dll": "d", "arch": None, "ret": "h"},
                {"dll": "d", "ret": "u64"},
            ],
        },
    )
    catalog = list(source.iter_functions("d.dll", arch))
    assert len(catalog) == 1 and catalog[0].ret == ret
    assert catalog[0] is source.lookup_exact("D.DLL", "Shared", arch)
    assert catalog[0].skip == ("unsupported" if arch == "x64" else None)
    assert set(source._sig_cache) == {("Shared", index)}


class _LookupOnlySource(sigdb.SignatureSource):
    @property
    def available(self) -> bool:
        return True

    def lookup(self, dll: str, func: str, arch: str) -> sigdb.FuncSig | None:
        return sigdb.FuncSig(func, dll, "v", ())


def test_lookup_only_custom_sources_default_to_empty_catalog() -> None:
    source = _LookupOnlySource()
    assert source.lookup("d", "Anything", "x86") is not None
    assert list(source.iter_functions("d", "x86")) == []
    assert list(sigdb.SignatureDatabase([source]).iter_functions("d", "x86")) == []
    assert list(sigdb.SignatureDatabase([]).iter_functions("d", "x86")) == []


def test_database_preserves_source_precedence_and_exact_names(tmp_path: Path) -> None:
    first = _source(
        tmp_path,
        {"Z": [{"dll": "d"}], "Same": [{"dll": "d", "skip": "unsupported"}]},
        filename="first",
    )
    second = _source(
        tmp_path,
        {"same": [{"dll": "d"}], "Same": [{"dll": "d", "ret": "u32"}], "A": [{"dll": "d"}]},
        filename="second",
        phnt=True,
    )
    db = sigdb.SignatureDatabase([_LookupOnlySource(), first, second])
    catalog = list(db.iter_functions("d", "x86"))
    assert [sig.name for sig in catalog] == ["Same", "Z", "A", "same"]
    assert catalog[0].skip == "unsupported" and catalog[0].source == "win32metadata"
    assert list(db.iter_functions("d", "x86")) == catalog
    db.add_source(second, first=True)
    catalog = list(db.iter_functions("d", "x86"))
    assert [sig.name for sig in catalog] == ["A", "Same", "same", "Z"]
    assert catalog[1].ret == "u32" and catalog[1].source == "phnt"


def test_missing_metadata_has_empty_catalog(tmp_path: Path) -> None:
    source = sigdb.Win32MetadataSource(str(tmp_path / "missing.json.gz"))
    assert list(source.iter_functions("kernel32", "x86")) == []


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_empty_and_foreign_arch_restrictions_never_become_unrestricted(tmp_path: Path, arch: str) -> None:
    source = _source(
        tmp_path,
        {
            "NoArchitectures": [{"dll": "d", "arch": []}],
            "ArmOnly": [{"dll": "d", "arch": ["arm64"]}],
            "Unrestricted": [{"dll": "d", "arch": None}],
        },
    )
    assert [sig.name for sig in source.iter_functions("d", arch)] == ["Unrestricted"]
    assert source.lookup("d", "NoArchitectures", arch) is None
    assert source.lookup("d", "ArmOnly", arch) is None
    raw = source._to_sig("NoArchitectures", 0, source._functions["NoArchitectures"][0])
    assert raw.arch == () and not raw.supports_arch(arch)


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_ineligible_first_source_cannot_shadow_eligible_declaration(tmp_path: Path, arch: str) -> None:
    first = _source(tmp_path, {"Shared": [{"dll": "d", "arch": ["arm64"]}]}, filename="first")
    second = _source(tmp_path, {"Shared": [{"dll": "d", "arch": [arch], "ret": "h"}]}, filename="second")
    db = sigdb.SignatureDatabase([first, second])
    catalog = list(db.iter_functions("d", arch))
    assert len(catalog) == 1 and catalog[0].ret == "h" and catalog[0].arch == (arch,)
    assert catalog[0] is second.lookup("d", "Shared", arch)


class _SignatureProbe:
    """Exercise binding without constructing an emulator or running native code."""

    lookup_api_signature = WindowsEmulator.lookup_api_signature
    _lookup_api_declaration = WindowsEmulator._lookup_api_declaration

    def __init__(self, db: sigdb.SignatureDatabase, arch: str) -> None:
        self.db = db
        self.arch = arch

    def get_signature_db(self) -> sigdb.SignatureDatabase:
        return self.db

    def _get_signature_arch(self) -> str:
        return self.arch

    def get_ptr_size(self) -> int:
        return 4 if self.arch == "x86" else 8


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_signature_binding_rejects_explicit_skip_and_ineligible_arch(tmp_path: Path, arch: str) -> None:
    source = _source(
        tmp_path,
        {
            "Skipped": [{"dll": "d", "skip": "unsupported transport"}],
            "WrongArch": [{"dll": "d", "arch": ["arm64"]}],
            "Safe": [{"dll": "d", "ret": "u32", "params": [["value", "u32"]]}],
        },
    )
    probe = _SignatureProbe(sigdb.SignatureDatabase([source]), arch)
    assert probe.lookup_api_signature("d", "Skipped") is None
    assert probe.lookup_api_signature("d", "WrongArch") is None
    assert probe.lookup_api_signature("d", "Safe") is source.lookup("d", "Safe", arch)


def test_binding_uses_exact_catalog_declaration_across_sources(tmp_path: Path) -> None:
    foreign = _source(
        tmp_path,
        {"Shared": [{"dll": "other", "conv": "cdecl", "params": [["a", "u32"], ["b", "u32"]]}]},
        filename="foreign",
    )
    exact = _source(tmp_path, {"Shared": [{"dll": "d", "params": [["a", "u32"]]}]}, filename="exact")
    db = sigdb.SignatureDatabase([foreign, exact])
    declaration = next(db.iter_functions("d", "x86"))
    assert declaration.dll == "d" and declaration.slot_count(4) == 1
    assert _SignatureProbe(db, "x86").lookup_api_signature("d", "Shared") is declaration


def test_unknown_module_does_not_acquire_foreign_execution_abi(tmp_path: Path) -> None:
    source = _source(tmp_path, {"Foreign": [{"dll": "kernel32", "params": [["a", "u32"]]}]})
    db = sigdb.SignatureDatabase([source])
    assert list(db.iter_functions("unknown_vendor", "x86")) == []
    assert _SignatureProbe(db, "x86").lookup_api_signature("unknown_vendor", "Foreign") is None


def test_alias_dll_binding_retains_its_own_exact_declaration(tmp_path: Path) -> None:
    source = _source(
        tmp_path,
        {"Shared": [{"dll": "kernel32", "params": [["a", "u32"]]}, {"dll": "psapi", "params": []}]},
    )
    db = sigdb.SignatureDatabase([source])
    declaration = next(db.iter_functions("psapi", "x86"))
    assert declaration.dll == "psapi"
    assert _SignatureProbe(db, "x86").lookup_api_signature("psapi", "Shared") is declaration


def test_binding_validates_architecture_even_for_custom_lookup_sources() -> None:
    class WrongArchitectureSource(_LookupOnlySource):
        def lookup(self, dll: str, func: str, arch: str) -> sigdb.FuncSig:
            return sigdb.FuncSig(func, dll, "u32", (), arch=("x64",))

    probe = _SignatureProbe(sigdb.SignatureDatabase([WrongArchitectureSource()]), "x86")
    assert probe.lookup_api_signature("d", "WrongArch") is None


@pytest.mark.parametrize(
    "arch,entry",
    [
        ("x86", {"ret": "f32"}),  # x87 result is not written by generic integer return.
        ("x64", {"ret": "f64"}),  # XMM0 result is not written.
        ("x86", {"ret": "u64"}),  # EDX:EAX result is not written.
        ("x86", {"ret": "st:RESULT:12"}),  # Hidden result pointer is absent from the slot layout.
        ("x64", {"ret": "st:RESULT:24"}),
        ("x64", {"params": [["value", "f64"]]}),  # Argument lives in XMM, not the integer register bank.
        ("x86", {"conv": "fastcall", "params": [["a", "u32"], ["b", "u32"]]}),
        ("x86", {"conv": "thiscall", "params": [["this", "p"]]}),
        ("x64", {"conv": "vectorcall", "params": [["value", "g"]]}),
        ("x86", {"conv": "cdecl", "variadic": True, "params": [["format", "s"]]}),
    ],
)
def test_unsupported_abi_is_visible_but_cannot_bind_for_generic_execution(tmp_path: Path, arch: str, entry: dict):
    source = _source(tmp_path, {"Unsupported": [{"dll": "d", **entry}]})
    db = sigdb.SignatureDatabase([source])
    declaration = next(db.iter_functions("d", arch))
    assert declaration.skip is None  # Lack of a skip flag is not proof of a supported ABI.
    assert _SignatureProbe(db, arch).lookup_api_signature("d", "Unsupported") is None


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_lookup_exact_rejects_foreign_dll_aliases_prefixes_and_name_case(tmp_path: Path, arch: str) -> None:
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
        assert provider.lookup_exact("unknown_vendor", "GetTickCount", arch) is None
        assert provider.lookup_exact("psapi", "GetTickCount", arch) is None
        assert provider.lookup_exact("kernel32", "EnumProcesses", arch) is None
        assert provider.lookup_exact("psapi", "EnumProcesses", arch) is None
        assert provider.lookup_exact("kernel32", "gettickcount", arch) is None
        shared = provider.lookup_exact("PSAPI.dll", "Shared", arch)
        assert shared is not None and shared.ret == "u32" and shared.dll == "PSAPI.DLL"
        exact = provider.lookup_exact("KERNEL32.DLL", "GetTickCount", arch)
        assert exact is not None and exact.dll == "kernel32"
        assert exact is provider.lookup("kernel32", "GetTickCount", arch)
        # Explicit alias binding means the caller supplies the target module/name.
        assert provider.lookup_exact("kernel32", "K32EnumProcesses", arch) is not None
        assert provider.lookup("unknown_vendor", "GetTickCount", arch) is exact
        assert provider.lookup("psapi", "EnumProcesses", arch) is not None


@pytest.mark.parametrize("arch,ret", [("x86", "i32"), ("x64", "i64")])
def test_lookup_exact_architecture_and_catalog_identity(tmp_path: Path, arch: str, ret: str) -> None:
    source = _source(
        tmp_path,
        {
            "Shared": [
                {"dll": "foreign", "ret": "v"},
                {"dll": "d", "arch": ["arm64"]},
                {"dll": "d", "arch": ["x64"], "ret": "i64"},
                {"dll": "d", "arch": ["x86"], "ret": "i32"},
            ],
            "Empty": [{"dll": "d", "arch": []}],
            "WrongArch": [{"dll": "d", "arch": ["arm64"]}],
            "Unrestricted": [{"dll": "d"}],
        },
    )
    db = sigdb.SignatureDatabase([source])
    for provider in (source, db):
        assert provider.lookup_exact("d", "Empty", arch) is None
        assert provider.lookup_exact("d", "WrongArch", arch) is None
        assert provider.lookup_exact("d", "Missing", arch) is None
        sig = provider.lookup_exact("D.DLL", "Shared", arch)
        assert sig is not None and sig.ret == ret and sig.arch == (arch,)
        assert {s.name: s for s in provider.iter_functions("d", arch)}["Shared"] is sig


def test_lookup_exact_source_precedence_preserves_unsupported_declarations(tmp_path: Path) -> None:
    foreign = _source(tmp_path, {"Shared": [{"dll": "other"}]}, filename="foreign")
    wrong_arch = _source(tmp_path, {"Shared": [{"dll": "d", "arch": ["arm64"]}]}, filename="wrong")
    skipped = _source(tmp_path, {"Shared": [{"dll": "d", "skip": "unsupported"}]}, filename="skipped")
    supported = _source(tmp_path, {"Shared": [{"dll": "d", "ret": "u32"}]}, filename="supported")
    db = sigdb.SignatureDatabase([foreign, wrong_arch, skipped, supported])
    sig = db.lookup_exact("d", "Shared", "x86")
    assert sig is not None and sig.skip == "unsupported"
    assert sig is next(db.iter_functions("d", "x86"))
    db.add_source(supported, first=True)
    assert db.lookup_exact("d", "Shared", "x86") is supported.lookup_exact("d", "Shared", "x86")


@pytest.mark.parametrize("bad", ["dll", "name", "arch"])
@pytest.mark.parametrize("override_exact", [False, True])
def test_lookup_exact_validates_custom_sources(bad: str, override_exact: bool) -> None:
    class CustomSource(_LookupOnlySource):
        def lookup(self, dll: str, func: str, arch: str) -> sigdb.FuncSig:
            return sigdb.FuncSig(
                name="OtherName" if bad == "name" else func,
                dll="foreign" if bad == "dll" else dll,
                ret="v",
                params=(),
                arch=("arm64",) if bad == "arch" else None,
            )

    if override_exact:
        # Even an override must satisfy the database's exact-match contract.
        class UncheckedSource(CustomSource):
            lookup_exact = CustomSource.lookup

        source = UncheckedSource()
    else:
        source = CustomSource()
        assert source.lookup_exact("d", "F", "x86") is None
    assert sigdb.SignatureDatabase([source]).lookup_exact("d", "F", "x86") is None


def test_lookup_exact_custom_source_and_missing_database(tmp_path: Path) -> None:
    custom = _LookupOnlySource()
    assert custom.lookup_exact("D.DLL", "F", "x86") is not None
    assert sigdb.SignatureDatabase([custom]).lookup_exact("D.DLL", "F", "x86") is not None
    assert sigdb.SignatureDatabase([]).lookup_exact("d", "F", "x86") is None
    missing = sigdb.Win32MetadataSource(str(tmp_path / "missing.json.gz"))
    assert missing.lookup_exact("d", "F", "x86") is None


def test_lookup_exact_converts_only_selected_signature(tmp_path: Path) -> None:
    source = _source(
        tmp_path,
        {"F": [{"dll": "foreign"}, {"dll": "d", "ret": "f64"}], "Unrelated": [{"dll": "d"}]},
    )
    assert not source._loaded
    sig = source.lookup_exact("d", "F", "x64")
    assert sig is not None and sig.ret == "f64" and sig.skip is None
    assert set(source._sig_cache) == {("F", 1)}
    assert source.lookup_exact("d", "F", "x64") is sig


@pytest.mark.parametrize("ptr_size", [4, 8])
@pytest.mark.parametrize("conv", [sigdb.CONV_CDECL, sigdb.CONV_STDCALL])
def test_emulation_supports_integer_and_pointer_transport(ptr_size: int, conv: str) -> None:
    sig = sigdb.FuncSig(
        "Safe",
        "d",
        "u32:STATUS",
        tuple(sigdb.ParamSig("value", code) for code in ("i32:ENUM", "u64", "b", "S", "p:f64", "ps:RESULT")),
        conv=conv,
    )
    assert sig.supports_emulation(ptr_size)
    assert sig.slot_count(ptr_size) == (7 if ptr_size == 4 else 6)
    assert sigdb.FuncSig("Void", "d", "v", ()).supports_emulation(ptr_size)


@pytest.mark.parametrize("ret", ["i64", "u64"])
def test_emulation_wide_integer_returns_require_x64(ret: str) -> None:
    sig = sigdb.FuncSig("Wide", "d", ret, ())
    assert not sig.supports_emulation(4)
    assert sig.supports_emulation(8)


@pytest.mark.parametrize("ptr_size", [4, 8])
@pytest.mark.parametrize("code", ["f32", "f64", "g", "st:RESULT:4", "st:RESULT:12/24", "arr:2:u32", "unknown"])
def test_emulation_rejects_float_aggregate_and_unknown_returns(ptr_size: int, code: str) -> None:
    assert not sigdb.FuncSig("Unsupported", "d", code, ()).supports_emulation(ptr_size)


@pytest.mark.parametrize("ptr_size", [4, 8])
@pytest.mark.parametrize("code", ["f32", "f64", "g", "st:VALUE:4", "st:VALUE:12/24", "arr:2:u32", "unknown", "v"])
def test_emulation_rejects_float_aggregate_and_unknown_parameters(ptr_size: int, code: str) -> None:
    sig = sigdb.FuncSig("Unsupported", "d", "u32", (sigdb.ParamSig("value", code),))
    assert not sig.supports_emulation(ptr_size)


@pytest.mark.parametrize("ptr_size", [4, 8])
@pytest.mark.parametrize("conv", ["fastcall", "thiscall", "vectorcall", "unknown"])
def test_emulation_rejects_unimplemented_conventions(ptr_size: int, conv: str) -> None:
    assert not sigdb.FuncSig("Unsupported", "d", "u32", (), conv=conv).supports_emulation(ptr_size)


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_emulation_rejects_skipped_variadic_and_wrong_architecture(ptr_size: int) -> None:
    assert not sigdb.FuncSig("Skipped", "d", "u32", (), skip="unsupported").supports_emulation(ptr_size)
    assert not sigdb.FuncSig("Variadic", "d", "u32", (), variadic=True).supports_emulation(ptr_size)
    other_arch = "x64" if ptr_size == 4 else "x86"
    assert not sigdb.FuncSig("OtherArch", "d", "u32", (), arch=(other_arch,)).supports_emulation(ptr_size)
    assert not sigdb.FuncSig("NoArch", "d", "u32", (), arch=()).supports_emulation(ptr_size)


@pytest.mark.parametrize("ptr_size", [0, 2, 16])
def test_emulation_rejects_invalid_pointer_sizes(ptr_size: int) -> None:
    assert not sigdb.FuncSig("F", "d", "u32", ()).supports_emulation(ptr_size)


def test_unsupported_emulation_never_removes_exact_declarations(tmp_path: Path) -> None:
    source = _source(tmp_path, {"Aggregate": [{"dll": "d", "ret": "st:RESULT:24"}]})
    db = sigdb.SignatureDatabase([source])
    sig = db.lookup_exact("d", "Aggregate", "x64")
    assert sig is not None and sig is next(db.iter_functions("d", "x64"))
    assert not sig.supports_emulation(8)


def test_dispatch_preserves_unsupported_exact_source_precedence(tmp_path: Path) -> None:
    unsupported = _source(tmp_path, {"F": [{"dll": "d", "ret": "f64"}]}, filename="unsupported")
    safe = _source(tmp_path, {"F": [{"dll": "d", "ret": "u32"}]}, filename="safe")
    db = sigdb.SignatureDatabase([unsupported, safe])
    assert db.lookup_exact("d", "F", "x64") is unsupported.lookup_exact("d", "F", "x64")
    assert _SignatureProbe(db, "x64").lookup_api_signature("d", "F") is None


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_vendor_gettickcount_collision_cannot_enable_generic_dispatch(tmp_path: Path, arch: str) -> None:
    source = _source(tmp_path, {"GetTickCount": [{"dll": "kernel32", "ret": "u32"}]})
    db = sigdb.SignatureDatabase([source])
    assert db.lookup("unknown_vendor", "GetTickCount", arch) is not None
    assert _SignatureProbe(db, arch).lookup_api_signature("unknown_vendor", "GetTickCount") is None


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_database_filters_custom_catalog_before_claiming_name_precedence(tmp_path: Path, arch: str) -> None:
    class UnfilteredSource(_LookupOnlySource):
        def iter_functions(self, dll: str, requested_arch: str):
            assert dll == "d" and requested_arch == arch
            yield sigdb.FuncSig("Shared", "foreign", "v", ())
            yield sigdb.FuncSig("Shared", "d", "v", (), arch=("arm64",))
            yield sigdb.FuncSig("EmptyArch", "d", "v", (), arch=())
            yield sigdb.FuncSig("ForeignOnly", "foreign", "v", ())
            yield first
            yield sigdb.FuncSig("First", "d", "u32", ())
            yield sigdb.FuncSig("first", "d", "u32", ())

    first = sigdb.FuncSig("First", "D.DLL", "f64", (), arch=(arch,), skip="unsupported")
    later = _source(
        tmp_path,
        {"Shared": [{"dll": "d"}], "First": [{"dll": "d"}], "EmptyArch": [{"dll": "d"}]},
    )
    db = sigdb.SignatureDatabase([UnfilteredSource(), later])
    catalog = list(db.iter_functions("D.DLL", arch))
    assert [sig.name for sig in catalog] == ["First", "first", "EmptyArch", "Shared"]
    assert catalog[0] is first  # Valid unsupported records retain precedence.
    assert catalog[-1] is later.lookup_exact("d", "Shared", arch)
    assert list(db.iter_functions("d", arch)) == catalog
    assert all(sigdb.normalize_dll(sig.dll) == "d" and sig.supports_arch(arch) for sig in catalog)


def test_database_reports_invalid_custom_catalog_record() -> None:
    class MalformedSource(_LookupOnlySource):
        name = "malformed"

        def iter_functions(self, dll: str, arch: str):
            yield {"name": "F", "dll": dll}

    db = sigdb.SignatureDatabase([MalformedSource()])
    with pytest.raises(TypeError, match="source 'malformed' iter_functions must yield FuncSig"):
        list(db.iter_functions("d", "x86"))
