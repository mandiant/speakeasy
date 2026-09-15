"""Unit tests for the Win32 API signature database (speakeasy.winenv.api.sigdb)."""

import gzip
import json

import pytest

from speakeasy.winenv.api import sigdb


def _write_db(
    path, functions, dll_aliases=None, name_prefixes=None, enums=None, structs=None, fmt=sigdb.SUPPORTED_FORMAT
):
    doc = {
        "format": fmt,
        "source": "test",
        "version": "test",
        "commit": None,
        "dll_aliases": dll_aliases or {},
        "name_prefixes": name_prefixes or {},
        "enums": enums or {},
        "structs": structs or {},
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
        ("p:u64", 4, 1),
        ("a:u16", 8, 1),
    ],
)
def test_param_slots(code, ptr_size, expected_slots):
    assert sigdb.ParamSig("x", code).slots(ptr_size) == expected_slots


@pytest.mark.parametrize(
    "code,pointee,elem32,elem64",
    [
        ("p", None, None, None),
        ("p:u32", "u32", 4, 4),
        ("p:h", "h", 4, 8),
        ("p:p", "p", 4, 8),
        ("p:u32:FLAGS", "u32:FLAGS", 4, 4),
        ("a:u16", "u16", 2, 2),
        ("a:st:FILETIME:8", "st:FILETIME:8", 8, 8),
        ("a", None, None, None),
        ("s", "u8", 1, 1),
        ("S", "u16", 2, 2),
        ("ps:X", None, None, None),
        ("u32", None, None, None),
    ],
)
def test_param_pointee(code, pointee, elem32, elem64):
    p = sigdb.ParamSig("x", code)
    assert p.pointee == pointee
    assert p.elem_size(4) == elem32
    assert p.elem_size(8) == elem64


def test_param_kind_and_flags():
    p = sigdb.ParamSig("lpFileName", "ps:SECURITY_ATTRIBUTES", "i?c")
    assert p.kind == "ps"
    assert p.qualifier == "SECURITY_ATTRIBUTES"
    assert p.is_in and not p.is_out and p.is_optional

    out = sigdb.ParamSig("lpThreadId", "p", "o?")
    assert out.is_out and not out.is_in

    # missing direction annotation is treated as input
    assert sigdb.ParamSig("x", "u32").is_in

    # only integer kinds carry an enum qualifier
    assert sigdb.ParamSig("dwShareMode", "u32:FILE_SHARE_MODE").enum == "FILE_SHARE_MODE"
    assert sigdb.ParamSig("dwShareMode", "u32:FILE_SHARE_MODE").kind == "u32"
    assert sigdb.ParamSig("x", "u32").enum is None
    assert p.enum is None


ACCESS = sigdb.EnumDef(
    "ACCESS",
    (
        ("READ_DATA", 0x1),
        ("LIST_DIRECTORY", 0x1),  # alias declared later loses
        ("WRITE_DATA", 0x2),
        ("READ_EA", 0x8),
        ("READ_ATTRIBUTES", 0x80),
        ("READ_CONTROL", 0x20000),
        ("SYNCHRONIZE", 0x100000),
        ("GENERIC_READ_LIKE", 0x120089),  # READ_DATA|READ_EA|READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE
        ("GENERIC_WRITE", 0x40000000),
    ),
    flags=True,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        (0x1, "READ_DATA"),
        (0x120089, "GENERIC_READ_LIKE"),
        (0x3, "WRITE_DATA|READ_DATA"),
        (0x40000001, "GENERIC_WRITE|READ_DATA"),
        (0x12008B, "GENERIC_READ_LIKE|WRITE_DATA"),
        (0x1000, "0x1000"),
        (0x1001, "READ_DATA|0x1000"),
        (0x0, "0x0"),
    ],
)
def test_enum_decode_flags(value, expected):
    assert ACCESS.decode(value) == expected


def test_enum_decode_plain():
    disposition = sigdb.EnumDef("D", (("CREATE_NEW", 1), ("CREATE_ALWAYS", 2), ("NONE", 0)))
    assert disposition.decode(2) == "CREATE_ALWAYS"
    assert disposition.decode(0) == "NONE"
    # a plain enum is never decomposed
    assert disposition.decode(3) == "0x3"


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


# -- Out buffer sizing ------------------------------------------------------

STRUCTS = {"SYSTEM_INFO": sigdb.StructDef("SYSTEM_INFO", 36, 48)}


def _out_sig(*params):
    return sigdb.FuncSig(name="f", dll="d", ret="v", params=tuple(params))


def _size(sig, index, values, ptr_size=4, memory=None):
    memory = memory or {}
    return sigdb.out_buffer_size(sig, index, values, ptr_size, STRUCTS.get, lambda addr, n: memory.get(addr))


def test_out_buffer_size_scalars_and_structs():
    sig = _out_sig(
        sigdb.ParamSig("lpdw", "p:u32", "o"),
        sigdb.ParamSig("ph", "p:h", "o"),
        sigdb.ParamSig("pv", "p", "o"),
        sigdb.ParamSig("info", "ps:SYSTEM_INFO", "o"),
        sigdb.ParamSig("unknown", "ps:NOPE", "o"),
        sigdb.ParamSig("sz", "s", "o"),
        sigdb.ParamSig("wsz", "S", "o"),
        sigdb.ParamSig("arr", "a:u16", "o"),
    )
    values = [0x1000] * len(sig.params)
    assert [_size(sig, i, values, 4) for i in range(len(sig.params))] == [4, 4, None, 36, None, 1, 2, None]
    assert [_size(sig, i, values, 8) for i in range(len(sig.params))] == [4, 8, None, 48, None, 1, 2, None]


def test_out_buffer_size_from_count_params():
    sig = _out_sig(
        sigdb.ParamSig("wide", "a:u16", "o", ("c", 1)),
        sigdb.ParamSig("nSize", "u32", "i"),
        sigdb.ParamSig("pv", "p", "o", ("n", 3)),
        sigdb.ParamSig("cb", "p", "i"),  # SIZE_T
        sigdb.ParamSig("fixed", "a:st:FILETIME:8", "o", ("k", 3)),
        sigdb.ParamSig("bytes", "a:u8", "o", ("n", 6)),
        sigdb.ParamSig("pcb", "p:u32", "i"),  # count behind a pointer
        sigdb.ParamSig("blob", "a", "o", ("c", 1)),  # element size unknown
        sigdb.ParamSig("bytes2", "a:u8", "o", ("n", 9)),
        sigdb.ParamSig("pcbOut", "p:u32", "o"),  # count is an output: unknown
    )
    values = [0x1000, 8, 0x2000, 0x30, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000]
    memory = {0x5000: 12}
    assert _size(sig, 0, values, 4, memory) == 16
    assert _size(sig, 2, values, 4, memory) == 0x30
    assert _size(sig, 4, values, 4, memory) == 24
    assert _size(sig, 5, values, 4, memory) == 12
    assert _size(sig, 7, values, 4, memory) is None
    assert _size(sig, 8, values, 4, memory) is None
    # NULL count pointer
    values[6] = 0
    assert _size(sig, 5, values, 4, memory) is None


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
        "MoveFileExW": [
            {
                "dll": "kernel32",
                "ret": "b",
                "params": [["lpExistingFileName", "S", "ic"], ["dwFlags", "u32:MOVE_FILE_FLAGS", "i"]],
            }
        ],
    }
    functions["GetSystemInfo"] = [{"dll": "kernel32", "ret": "v", "params": [["lpSystemInfo", "ps:SYSTEM_INFO", "o"]]}]
    functions["GetPrivateProfileStringW"] = [
        {
            "dll": "kernel32",
            "ret": "u32",
            "params": [["lpReturnedString", "a:u16", "o?", {"c": 1}], ["nSize", "u32", "i"]],
        }
    ]
    enums = {
        "MOVE_FILE_FLAGS": {"f": True, "v": [["MOVEFILE_REPLACE_EXISTING", 1], ["MOVEFILE_COPY_ALLOWED", 2]]},
    }
    structs = {"SYSTEM_INFO": {"s": [36, 48]}}
    path = _write_db(
        tmp_path / "sigs.json.gz",
        functions,
        dll_aliases={"psapi": "kernel32"},
        name_prefixes={"kernel32": ["K32"]},
        enums=enums,
        structs=structs,
    )
    return sigdb.Win32MetadataSource(path)


def test_source_basic_lookup(small_db):
    assert small_db.available
    assert len(small_db) == 8
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


def test_source_enum_lookup(small_db):
    sig = small_db.lookup("kernel32", "MoveFileExW", "x86")
    assert sig.params[1].enum == "MOVE_FILE_FLAGS"
    enum = small_db.lookup_enum("MOVE_FILE_FLAGS")
    assert enum is not None and enum.flags
    assert enum.decode(3) == "MOVEFILE_COPY_ALLOWED|MOVEFILE_REPLACE_EXISTING"
    assert small_db.lookup_enum("MOVE_FILE_FLAGS") is enum
    assert small_db.lookup_enum("NOPE") is None


def test_source_struct_and_buffer_length(small_db):
    struct = small_db.lookup_struct("SYSTEM_INFO")
    assert struct is not None and struct.size(4) == 36 and struct.size(8) == 48
    assert small_db.lookup_struct("SYSTEM_INFO") is struct
    assert small_db.lookup_struct("NOPE") is None
    sig = small_db.lookup("kernel32", "GetPrivateProfileStringW", "x86")
    assert sig.params[0].buffer_len == ("c", 1)
    assert sig.params[1].buffer_len is None


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
    # enums and structs are looked up across sources too; a source without them answers None
    assert db.lookup_enum("MOVE_FILE_FLAGS").name == "MOVE_FILE_FLAGS"
    assert db.lookup_struct("SYSTEM_INFO").size32 == 36
    assert sigdb.SignatureDatabase([]).lookup_enum("MOVE_FILE_FLAGS") is None
    assert sigdb.SignatureDatabase([]).lookup_struct("SYSTEM_INFO") is None


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


def test_bundled_database_enums():
    db = _bundled()
    create_file = db.lookup("kernel32", "CreateFileW", "x86")
    assert create_file.params[1].enum == "FILE_ACCESS_FLAGS"
    assert create_file.params[4].enum == "FILE_CREATION_DISPOSITION"
    assert db.lookup_enum("FILE_CREATION_DISPOSITION").decode(2) == "CREATE_ALWAYS"
    assert db.lookup_enum("FILE_SHARE_MODE").decode(0) == "FILE_SHARE_NONE"
    assert db.lookup_enum("FILE_SHARE_MODE").decode(3) == "FILE_SHARE_WRITE|FILE_SHARE_READ"
    # GENERIC_* come from enum_extra in the overrides
    assert db.lookup_enum("FILE_ACCESS_FLAGS").decode(0xC0000000) == "GENERIC_READ|GENERIC_WRITE"
    assert db.lookup_enum("PAGE_PROTECTION_FLAGS").decode(0x40) == "PAGE_EXECUTE_READWRITE"
    assert db.lookup_enum("VIRTUAL_ALLOCATION_TYPE").decode(0x3000) == "MEM_RESERVE|MEM_COMMIT"


def test_bundled_database_structs_and_buffers():
    db = _bundled()
    assert db.lookup_struct("SYSTEM_INFO").size(4) == 36
    assert db.lookup_struct("SYSTEM_INFO").size(8) == 48
    assert db.lookup_struct("OVERLAPPED").size(4) == 20
    assert db.lookup_struct("OVERLAPPED").size(8) == 32
    # anonymous nested unions lay out too
    assert db.lookup_struct("LARGE_INTEGER").size(8) == 8
    assert db.lookup_struct("IN_ADDR").size(4) == 4
    sig = db.lookup("kernel32", "GetPrivateProfileStringW", "x86")
    assert sig.params[3].code == "a:u16" and sig.params[3].buffer_len == ("c", 4)
    assert db.lookup("kernel32", "GetVolumeInformationW", "x86").params[3].code == "p:u32"
    # every function is now laid out; nothing is skipped
    src = db.sources[0]
    assert not any(e.get("skip") for entries in src._functions.values() for e in entries)
