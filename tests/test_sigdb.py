"""Unit tests for the Win32 API signature database (speakeasy.winenv.api.sigdb)."""

import gzip
import json

import pytest

from speakeasy.winenv.api import sigdb


def _write_db(path, functions, dll_aliases=None, name_prefixes=None, fmt=sigdb.SUPPORTED_FORMAT):
    doc = {
        "format": fmt,
        "source": "test",
        "version": "test",
        "commit": None,
        "dll_aliases": dll_aliases or {},
        "name_prefixes": name_prefixes or {},
        "functions": functions,
    }
    with gzip.open(path, "wb") as f:
        f.write(json.dumps(doc).encode("utf-8"))
    return str(path)


# -- ParamSig / FuncSig -----------------------------------------------------


@pytest.mark.parametrize(
    "code,ptr_size,expected_slots",
    [
        ("u32", 4, 1),
        ("u32", 8, 1),
        ("u8", 4, 1),
        ("u64", 4, 2),
        ("u64", 8, 1),
        ("f64", 4, 2),
        ("f32", 4, 1),
        ("p", 4, 1),
        ("p", 8, 1),
        ("S", 4, 1),
        ("ps:FILETIME", 8, 1),
        ("g", 4, 4),
        ("g", 8, 1),  # aggregates larger than 8 bytes go by reference on Win64
        ("st:FILETIME:8", 4, 2),
        ("st:FILETIME:8", 8, 1),
        ("st:RECT:16", 4, 4),
        ("st:X:12/24", 4, 3),
        ("st:X:12/24", 8, 1),
    ],
)
def test_param_slots(code, ptr_size, expected_slots):
    assert sigdb.ParamSig("x", code).slots(ptr_size) == expected_slots


def test_param_kind_and_flags():
    p = sigdb.ParamSig("lpFileName", "ps:SECURITY_ATTRIBUTES", "i?c")
    assert p.kind == "ps"
    assert p.qualifier == "SECURITY_ATTRIBUTES"
    assert p.is_in and not p.is_out and p.is_optional

    out = sigdb.ParamSig("lpThreadId", "p", "o?")
    assert out.is_out and not out.is_in

    # missing direction annotation is treated as input
    assert sigdb.ParamSig("x", "u32").is_in


def test_values_from_slots_x86_joins_and_masks():
    sig = sigdb.FuncSig(
        name="f",
        dll="d",
        ret="v",
        params=(
            sigdb.ParamSig("a", "u16"),
            sigdb.ParamSig("b", "u64"),
            sigdb.ParamSig("c", "p"),
            sigdb.ParamSig("d", "st:FILETIME:8"),
        ),
    )
    assert sig.slot_layout(4) == [1, 2, 1, 2]
    assert sig.slot_count(4) == 6
    slots = [0xDEAD1234, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555]
    assert sig.values_from_slots(slots, 4) == [
        0x1234,
        0x2222222211111111,
        0x33333333,
        0x5555555544444444,
    ]


def test_values_from_slots_x64_masks_narrow_ints():
    sig = sigdb.FuncSig(name="f", dll="d", ret="v", params=(sigdb.ParamSig("a", "b"), sigdb.ParamSig("b", "u64")))
    assert sig.slot_count(8) == 2
    assert sig.values_from_slots([0xFFFFFFFF00000001, 0x0123456789ABCDEF], 8) == [1, 0x0123456789ABCDEF]


def test_func_sig_arch_filter():
    sig = sigdb.FuncSig(name="f", dll="d", ret="v", params=(), arch=("x86",))
    assert sig.supports_arch("x86")
    assert not sig.supports_arch("x64")
    assert sigdb.FuncSig(name="f", dll="d", ret="v", params=()).supports_arch("x64")


def test_normalize_dll():
    assert sigdb.normalize_dll("KERNEL32.dll") == "kernel32"
    assert sigdb.normalize_dll("winspool.drv") == "winspool"
    assert sigdb.normalize_dll("ntdll") == "ntdll"


# -- Win32MetadataSource ----------------------------------------------------


@pytest.fixture
def small_db(tmp_path):
    functions = {
        "CreateFileW": [
            {
                "dll": "kernel32",
                "ret": "h",
                "params": [["lpFileName", "S", "ic"], ["dwDesiredAccess", "u32", "i"]],
                "sle": True,
            }
        ],
        "K32EnumProcesses": [
            {"dll": "kernel32", "ret": "b", "params": [["lpidProcess", "p", "o"], ["cb", "u32", "i"]]}
        ],
        "wsprintfA": [
            {
                "dll": "user32",
                "ret": "i32",
                "params": [["param0", "s", "o"], ["param1", "s", "ic"]],
                "variadic": True,
                "conv": "cdecl",
            }
        ],
        "SQLBindCol": [
            {"dll": "odbc32", "ret": "i16", "params": [["BufferLength", "i64", "i"]], "arch": ["x64", "arm64"]},
            {"dll": "odbc32", "ret": "i16", "params": [["BufferLength", "i32", "i"]], "arch": ["x86"]},
        ],
        "Broken": [{"dll": "foo", "ret": "p", "params": [], "skip": "param x: unknown type"}],
    }
    path = _write_db(
        tmp_path / "sigs.json.gz",
        functions,
        dll_aliases={"psapi": "kernel32"},
        name_prefixes={"kernel32": ["K32"]},
    )
    return sigdb.Win32MetadataSource(path)


def test_source_basic_lookup(small_db):
    assert small_db.available
    assert len(small_db) == 5
    sig = small_db.lookup("KERNEL32.dll", "CreateFileW", "x86")
    assert sig is not None
    assert sig.dll == "kernel32"
    assert sig.ret == "h"
    assert sig.conv == sigdb.CONV_STDCALL
    assert sig.set_last_error
    assert [p.name for p in sig.params] == ["lpFileName", "dwDesiredAccess"]
    assert sig.slot_count(4) == 2
    assert sig.source == "win32metadata"
    # cached
    assert small_db.lookup("kernel32", "CreateFileW", "x86") is sig


def test_source_unknown_function(small_db):
    assert small_db.lookup("kernel32", "DoesNotExist", "x86") is None


def test_source_dll_alias_and_name_prefix(small_db):
    # psapi!EnumProcesses is recorded by win32metadata as KERNEL32!K32EnumProcesses
    sig = small_db.lookup("psapi.dll", "EnumProcesses", "x86")
    assert sig is not None
    assert sig.name == "K32EnumProcesses"
    assert sig.dll == "kernel32"


def test_source_name_only_match_when_dll_differs(small_db):
    # forwarders and api-sets: trust the function name when the DLL is unknown
    sig = small_db.lookup("api-ms-win-core-file-l1-1-0", "CreateFileW", "x64")
    assert sig is not None and sig.dll == "kernel32"


def test_source_variadic_and_cdecl(small_db):
    sig = small_db.lookup("user32", "wsprintfA", "x86")
    assert sig.variadic
    assert sig.conv == sigdb.CONV_CDECL


def test_source_arch_specific_declarations(small_db):
    x86 = small_db.lookup("odbc32", "SQLBindCol", "x86")
    x64 = small_db.lookup("odbc32", "SQLBindCol", "x64")
    assert x86.params[0].code == "i32"
    assert x64.params[0].code == "i64"
    assert x86 is not x64


def test_source_skip_marker_preserved(small_db):
    sig = small_db.lookup("foo", "Broken", "x86")
    assert sig is not None and sig.skip


def test_source_missing_file(tmp_path, caplog):
    src = sigdb.Win32MetadataSource(str(tmp_path / "nope.json.gz"))
    assert not src.available
    assert src.lookup("kernel32", "CreateFileW", "x86") is None
    assert len(src) == 0


def test_source_wrong_format(tmp_path):
    path = _write_db(tmp_path / "old.json.gz", {"X": [{"dll": "d", "ret": "v", "params": []}]}, fmt=999)
    src = sigdb.Win32MetadataSource(path)
    assert not src.available


# -- SignatureDatabase ------------------------------------------------------


class _StaticSource(sigdb.SignatureSource):
    name = "static"

    def __init__(self, sigs):
        self.sigs = sigs

    @property
    def available(self):
        return bool(self.sigs)

    def lookup(self, dll, func, arch):
        return self.sigs.get(func)


def test_database_is_pluggable_and_ordered(small_db):
    custom = sigdb.FuncSig(name="CreateFileW", dll="custom", ret="v", params=(), source="static")
    db = sigdb.SignatureDatabase([small_db])
    assert db.lookup("kernel32", "CreateFileW", "x86").dll == "kernel32"

    db.add_source(_StaticSource({"CreateFileW": custom}), first=True)
    assert db.lookup("kernel32", "CreateFileW", "x86") is custom

    db = sigdb.SignatureDatabase([small_db])
    db.add_source(_StaticSource({"LdrLoadDll": custom}))
    assert db.lookup("ntdll", "LdrLoadDll", "x86") is custom
    assert db.available


def test_database_empty():
    db = sigdb.SignatureDatabase([])
    assert not db.available
    assert db.lookup("kernel32", "CreateFileW", "x86") is None


# -- bundled database -------------------------------------------------------


def _bundled():
    db = sigdb.get_default_database()
    if not db.available:
        pytest.skip("bundled signature database not generated (run scripts/gen_win32_signatures.py)")
    return db


def test_bundled_database_known_signatures():
    db = _bundled()
    create_file = db.lookup("kernel32", "CreateFileW", "x86")
    assert [p.name for p in create_file.params] == [
        "lpFileName",
        "dwDesiredAccess",
        "dwShareMode",
        "lpSecurityAttributes",
        "dwCreationDisposition",
        "dwFlagsAndAttributes",
        "hTemplateFile",
    ]
    assert create_file.params[0].code == "S"
    assert create_file.ret == "h"
    assert create_file.slot_count(4) == 7

    assert db.lookup("psapi", "EnumProcesses", "x64").name == "K32EnumProcesses"
    assert db.lookup("user32", "wsprintfA", "x86").variadic
    assert db.lookup("wldap32", "ldap_bind_sA", "x86").conv == sigdb.CONV_CDECL
    # 64-bit scalars take two slots on x86
    assert db.lookup("winhvplatform", "WHvMapGpaRange", "x86").slot_count(4) == 7
    # undocumented natives are not covered by win32metadata
    assert db.lookup("ntdll", "LdrLoadDll", "x86") is None
