"""Tests for scripts/gen_win32_signatures.py using a miniature win32json tree."""

import gzip
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "scripts" / "gen_win32_signatures.py"
OVERRIDES = REPO_ROOT / "scripts" / "win32_overrides.json"


@pytest.fixture(scope="module")
def gen() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_win32_signatures", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _native(name: str) -> dict[str, Any]:
    return {"Kind": "Native", "Name": name}


def _ref(api: str, name: str, target: str = "Default") -> dict[str, Any]:
    return {"Kind": "ApiRef", "Name": name, "TargetKind": target, "Api": api, "Parents": []}


def _ptr(child: dict[str, Any]) -> dict[str, Any]:
    return {"Kind": "PointerTo", "Child": child}


def _typedef(name: str, definition: dict[str, Any], **extra: Any) -> dict[str, Any]:
    td: dict[str, Any] = {
        "Name": name,
        "Architectures": [],
        "Platform": None,
        "Kind": "NativeTypedef",
        "AlsoUsableFor": None,
        "Def": definition,
        "FreeFunc": None,
        "InvalidHandleValue": None,
    }
    td.update(extra)
    return td


def _struct(
    name: str, fields: list[tuple[str, dict[str, Any]]], kind: str = "Struct", packing: int = 0
) -> dict[str, Any]:
    return {
        "Name": name,
        "Architectures": [],
        "Platform": None,
        "Kind": kind,
        "Size": 0,
        "PackingSize": packing,
        "Attrs": [],
        "Fields": [{"Name": n, "Type": t, "Attrs": []} for n, t in fields],
        "NestedTypes": [],
    }


def _with_anonymous_union() -> dict[str, Any]:
    """
    struct WITH_ANON { UINT32 tag; union { UINT64 q; struct { UINT32 lo, hi; } s; } u; }
    as win32metadata emits it: the union is an anonymous NestedType referenced
    with an empty Parents chain, and its inner struct with Parents=[union].
    """
    inner = _struct("_s_e__Struct", [("lo", _native("UInt32")), ("hi", _native("UInt32"))])
    union = _struct(
        "_u_e__Union",
        [
            ("q", _native("UInt64")),
            ("s", {**_ref("Foundation", "_s_e__Struct"), "Parents": ["_u_e__Union"]}),
        ],
        kind="Union",
    )
    union["NestedTypes"] = [inner]
    outer = _struct("WITH_ANON", [("tag", _native("UInt32")), ("u", _ref("Foundation", "_u_e__Union"))])
    outer["NestedTypes"] = [union]
    return outer


def _enum(name: str, values: list[tuple[str, int]], flags: bool = False, base: str = "UInt32") -> dict[str, Any]:
    return {
        "Name": name,
        "Architectures": [],
        "Platform": None,
        "Kind": "Enum",
        "Flags": flags,
        "Scoped": False,
        "IntegerBase": base,
        "Values": [{"Name": n, "Value": v} for n, v in values],
    }


def _func(
    name: str, dll: str, ret: dict[str, Any], params: list[tuple[str, dict[str, Any], list[Any]]], **extra: Any
) -> dict[str, Any]:
    fn = {
        "Name": name,
        "SetLastError": False,
        "DllImport": dll,
        "ReturnType": ret,
        "ReturnAttrs": [],
        "Architectures": [],
        "Platform": None,
        "Attrs": [],
        "Params": [{"Name": n, "Type": t, "Attrs": a} for n, t, a in params],
    }
    fn.update(extra)
    return fn


@pytest.fixture
def mini_win32json(tmp_path: Path) -> Path:
    api = tmp_path / "win32json" / "api"
    api.mkdir(parents=True)
    (tmp_path / "win32json" / "version.txt").write_text("0.0.1-test")

    foundation = {
        "Constants": [],
        "UnicodeAliases": [],
        "Functions": [],
        "Types": [
            _typedef("HANDLE", _native("IntPtr"), FreeFunc="CloseHandle", InvalidHandleValue=0),
            _typedef("HWND", _native("IntPtr")),
            _typedef("LPARAM", _native("IntPtr")),
            _typedef("BOOL", _native("Int32")),
            _typedef("BOOLEAN", _native("Byte")),
            _typedef("PSTR", _ptr(_native("Byte"))),
            _typedef("PWSTR", _ptr(_native("Char"))),
            _typedef("HRESULT", _native("Int32")),
            _struct("FILETIME", [("dwLowDateTime", _native("UInt32")), ("dwHighDateTime", _native("UInt32"))]),
            _struct("LARGE_INTEGER", [("QuadPart", _native("Int64"))]),
            _struct(
                "MIXED",
                [("a", _native("Byte")), ("p", _ptr(_native("Void"))), ("b", _native("UInt16"))],
            ),
            _struct(
                "PACKED",
                [("a", _native("Byte")), ("q", _native("UInt64"))],
                packing=1,
            ),
            _struct(
                "WITH_ARRAY",
                [
                    (
                        "abFlags",
                        {"Kind": "Array", "Shape": {"Size": 6}, "Child": _native("Byte")},
                    ),
                    ("ft", _ref("Foundation", "FILETIME")),
                ],
            ),
            _struct("U", [("x", _native("UInt32")), ("ft", _ref("Foundation", "FILETIME"))], kind="Union"),
            _with_anonymous_union(),
            _struct(
                "POINTY",
                [
                    ("a", _native("Byte")),
                    ("p", _ptr(_native("Void"))),
                    ("b", _native("UInt16")),
                    ("name", {"Kind": "Array", "Shape": {"Size": 3}, "Child": _native("Char")}),
                ],
            ),
            _enum("FLAGS", [("A", 1), ("B", 2)], flags=True),
            _enum("DISPOSITION", [("FIRST", 1), ("NEGATIVE", -1)], base="Int32"),
            _enum("UNREFERENCED", [("X", 1)]),
        ],
    }
    foundation["Constants"] = [
        {"Name": "EXTRA", "Type": _native("UInt32"), "Value": 16, "ValueType": "Int", "Attrs": []},
        {"Name": "NOT_AN_INT", "Type": _ref("Foundation", "PWSTR"), "Value": "x", "ValueType": "String", "Attrs": []},
    ]
    test_ns = {
        "Constants": [],
        "UnicodeAliases": [],
        "Types": [],
        "Functions": [
            _func(
                "CreateFileW",
                "KERNEL32.dll",
                _ref("Foundation", "HANDLE"),
                [
                    ("lpFileName", _ref("Foundation", "PWSTR"), ["In", "Const"]),
                    ("dwDesiredAccess", _native("UInt32"), ["In"]),
                    ("lpSecurityAttributes", _ptr(_ref("Foundation", "FILETIME")), ["In", "Optional"]),
                    ("dwFlags", _ref("Foundation", "FLAGS"), ["In"]),
                    ("disposition", _ref("Foundation", "DISPOSITION"), ["In"]),
                    ("hTemplateFile", _ref("Foundation", "HANDLE"), ["In", "Optional"]),
                    ("hwnd", _ref("Foundation", "HWND"), ["In"]),
                    ("lParam", _ref("Foundation", "LPARAM"), ["In"]),
                    ("ok", _ref("Foundation", "BOOL"), ["In"]),
                    ("okay", _ref("Foundation", "BOOLEAN"), ["In"]),
                    ("cb", _ref("Foundation", "LPTHREAD_START_ROUTINE", "FunctionPointer"), ["In"]),
                    ("pUnk", _ref("System.Com", "IUnknown", "Com"), ["In"]),
                    ("ppOut", _ptr(_ptr(_native("Void"))), ["Out"]),
                    ("buffer", {"Kind": "LPArray", "Child": _native("Byte")}, ["Out"]),
                    ("name", _ref("Foundation", "PSTR"), ["Out"]),
                    ("lpdwSize", _ptr(_native("UInt32")), ["Out"]),
                    ("phHandle", _ptr(_ref("Foundation", "HANDLE")), ["Out"]),
                    ("pFlags", _ptr(_ref("Foundation", "FLAGS")), ["Out"]),
                    ("pv", _ptr(_native("Void")), ["Out", {"Kind": "MemorySize", "BytesParamIndex": 1}]),
                    (
                        "wide",
                        {"Kind": "LPArray", "Child": _native("Char"), "CountParamIndex": 1, "CountConst": -1},
                        ["Out"],
                    ),
                    (
                        "fixed",
                        {
                            "Kind": "LPArray",
                            "Child": _ref("Foundation", "FILETIME"),
                            "CountParamIndex": -1,
                            "CountConst": 3,
                        },
                        ["Out"],
                    ),
                ],
                SetLastError=True,
            ),
            _func(
                "ByValue",
                "mapi32.dll",
                _ref("Foundation", "FILETIME"),
                [
                    ("ft", _ref("Foundation", "FILETIME"), ["In"]),
                    ("li", _ref("Foundation", "LARGE_INTEGER"), ["In"]),
                    ("mixed", _ref("Foundation", "MIXED"), ["In"]),
                    ("packed", _ref("Foundation", "PACKED"), ["In"]),
                    ("arr", _ref("Foundation", "WITH_ARRAY"), ["In"]),
                    ("u", _ref("Foundation", "U"), ["In"]),
                    ("guid", _native("Guid"), ["In"]),
                    ("d", _native("Double"), ["In"]),
                    ("f", _native("Single"), ["In"]),
                    ("q", _native("UInt64"), ["In"]),
                    ("anon", _ref("Foundation", "WITH_ANON"), ["In"]),
                    ("panon", _ptr(_ref("Foundation", "WITH_ANON")), ["Out"]),
                    ("ppointy", _ptr(_ref("Foundation", "POINTY")), ["In"]),
                ],
            ),
            _func(
                "wsprintfA",
                "USER32.dll",
                _native("Int32"),
                [("param0", _ref("Foundation", "PSTR"), ["Out"]), ("param1", _ref("Foundation", "PSTR"), ["In"])],
            ),
            _func("ldap_bind_sA", "WLDAP32.dll", _native("UInt32"), []),
            _func(
                "OnlyX86",
                "odbc32.dll",
                _native("Int16"),
                [("n", _native("Int32"), ["In"])],
                Architectures=["X86"],
            ),
            _func(
                "Unknown",
                "foo.dll",
                _native("Void"),
                [("x", _ref("Nowhere", "MISSING_TYPE"), ["In"])],
            ),
            _func("Dup", "a.dll", _native("Void"), []),
        ],
    }
    other_ns = {
        "Constants": [],
        "UnicodeAliases": [],
        "Types": [],
        # identical redeclaration in another namespace is folded; a different one is kept
        "Functions": [_func("Dup", "a.dll", _native("Void"), []), _func("Dup", "b.dll", _native("Void"), [])],
    }
    (api / "Foundation.json").write_text(json.dumps(foundation))
    (api / "Test.json").write_text(json.dumps(test_ns))
    (api / "Other.json").write_text(json.dumps(other_ns))
    return tmp_path / "win32json"


def test_generate_resolves_types(gen: ModuleType, mini_win32json: Path) -> None:
    doc, stats = gen.generate(str(mini_win32json), str(OVERRIDES))
    assert doc["format"] == gen.FORMAT_VERSION
    assert doc["version"] == "0.0.1-test"
    assert doc["dll_aliases"]["psapi"] == "kernel32"
    assert doc["name_prefixes"]["kernel32"] == ["K32"]

    (cf,) = doc["functions"]["CreateFileW"]
    assert cf["dll"] == "kernel32"
    assert cf["ret"] == "h"
    assert cf["sle"] is True
    assert "conv" not in cf and "skip" not in cf
    assert cf["params"] == [
        ["lpFileName", "S", "ic"],
        ["dwDesiredAccess", "u32", "i"],
        ["lpSecurityAttributes", "ps:FILETIME", "i?"],
        ["dwFlags", "u32:FLAGS", "i"],
        ["disposition", "i32:DISPOSITION", "i"],
        ["hTemplateFile", "h", "i?"],
        ["hwnd", "h", "i"],
        ["lParam", "p", "i"],
        ["ok", "b", "i"],
        ["okay", "B", "i"],
        ["cb", "p", "i"],
        ["pUnk", "p", "i"],
        ["ppOut", "p:p", "o"],
        ["buffer", "a:u8", "o"],
        ["name", "s", "o"],
        ["lpdwSize", "p:u32", "o"],
        ["phHandle", "p:h", "o"],
        ["pFlags", "p:u32:FLAGS", "o"],
        ["pv", "p", "o", {"n": 1}],
        ["wide", "a:u16", "o", {"c": 1}],
        ["fixed", "a:st:FILETIME:8", "o", {"k": 3}],
    ]
    # structs some parameter points at are laid out for both pointer sizes, with field offsets
    assert doc["structs"]["FILETIME"] == {
        "s": [8, 8],
        "f": [["dwLowDateTime", "u32", 0, 0], ["dwHighDateTime", "u32", 4, 4]],
    }
    assert "MIXED" not in doc["structs"]  # only referenced by value, never pointed at


def test_generate_enum_table(gen: ModuleType, mini_win32json: Path, tmp_path: Path) -> None:
    doc, stats = gen.generate(str(mini_win32json), str(OVERRIDES))
    # only enums some function references are carried; negative members are masked
    assert set(doc["enums"]) == {"FLAGS", "DISPOSITION"}
    assert doc["enums"]["FLAGS"] == {"v": [["A", 1], ["B", 2]], "f": True}
    assert doc["enums"]["DISPOSITION"] == {"v": [["FIRST", 1], ["NEGATIVE", 0xFFFFFFFF]]}
    assert stats["enums"] == 2

    # enum_extra appends named constants to an enum
    overrides = json.loads(OVERRIDES.read_text())
    overrides["enum_extra"] = {"FLAGS": ["EXTRA", "A"], "UNREFERENCED": ["EXTRA"]}
    path = tmp_path / "overrides.json"
    path.write_text(json.dumps(overrides))
    doc, _ = gen.generate(str(mini_win32json), str(path))
    assert doc["enums"]["FLAGS"]["v"] == [["A", 1], ["B", 2], ["EXTRA", 16]]

    overrides["enum_extra"] = {"FLAGS": ["NOT_AN_INT"]}
    path.write_text(json.dumps(overrides))
    with pytest.raises(SystemExit, match="NOT_AN_INT"):
        gen.generate(str(mini_win32json), str(path))


def test_generate_by_value_struct_sizes(gen: ModuleType, mini_win32json: Path) -> None:
    doc, _ = gen.generate(str(mini_win32json), str(OVERRIDES))
    (bv,) = doc["functions"]["ByValue"]
    assert bv["ret"] == "st:FILETIME:8"
    codes = dict((p[0], p[1]) for p in bv["params"])
    assert codes["ft"] == "st:FILETIME:8"
    assert codes["li"] == "st:LARGE_INTEGER:8"
    # byte + pointer + uint16 with natural alignment: 12 bytes on x86, 24 on x64
    assert codes["mixed"] == "st:MIXED:12/24"
    # pragma pack(1) defeats padding
    assert codes["packed"] == "st:PACKED:9"
    # 6-byte array then a 4-aligned struct: 6 -> 8 + 8 = 16
    assert codes["arr"] == "st:WITH_ARRAY:16"
    assert codes["u"] == "st:U:8"
    assert codes["guid"] == "g"
    assert codes["d"] == "f64"
    assert codes["f"] == "f32"
    assert codes["q"] == "u64"
    # anonymous nested union: 4 (tag) + pad to 8 + 8 = 16
    assert codes["anon"] == "st:WITH_ANON:16"
    assert codes["panon"] == "ps:WITH_ANON"
    structs = doc["structs"]
    assert structs["WITH_ANON"] == {
        "s": [16, 16],
        "f": [["tag", "u32", 0, 0], ["u", "st:WITH_ANON._u_e__Union:8", 8, 8]],
    }
    # nested types are keyed by their path and emitted transitively
    assert structs["WITH_ANON._u_e__Union"] == {
        "s": [8, 8],
        "u": True,
        "f": [["q", "u64", 0, 0], ["s", "st:WITH_ANON._u_e__Union._s_e__Struct:8", 0, 0]],
    }
    assert structs["WITH_ANON._u_e__Union._s_e__Struct"]["f"] == [["lo", "u32", 0, 0], ["hi", "u32", 4, 4]]
    # pointer-bearing struct: offsets differ per pointer size
    assert structs["POINTY"] == {
        "s": [16, 24],
        "f": [["a", "u8", 0, 0], ["p", "p", 4, 8], ["b", "u16", 8, 16], ["name", "arr:3:u16", 10, 18]],
    }


def test_generate_applies_overrides(gen: ModuleType, mini_win32json: Path) -> None:
    doc, stats = gen.generate(str(mini_win32json), str(OVERRIDES))
    (ws,) = doc["functions"]["wsprintfA"]
    assert ws["variadic"] is True and ws["conv"] == "cdecl"
    (ldap,) = doc["functions"]["ldap_bind_sA"]
    assert ldap["conv"] == "cdecl"
    assert stats["variadic"] == 1
    assert stats["cdecl"] == 2


def test_generate_arch_skip_and_duplicates(gen: ModuleType, mini_win32json: Path) -> None:
    doc, stats = gen.generate(str(mini_win32json), str(OVERRIDES))
    (x86,) = doc["functions"]["OnlyX86"]
    assert x86["arch"] == ["x86"]

    (unknown,) = doc["functions"]["Unknown"]
    assert unknown["skip"].startswith("param x: unknown type Nowhere.MISSING_TYPE")
    assert stats["skipped"] == 1

    dups = doc["functions"]["Dup"]
    assert [d["dll"] for d in dups] == ["a", "b"]
    assert stats["duplicates"] == 1


def test_write_output_is_reproducible(gen: ModuleType, mini_win32json: Path, tmp_path: Path) -> None:
    doc, _ = gen.generate(str(mini_win32json), str(OVERRIDES))
    out1 = tmp_path / "a.json.gz"
    out2 = tmp_path / "b.json.gz"
    gen.write_output(doc, str(out1))
    gen.write_output(doc, str(out2))
    assert out1.read_bytes() == out2.read_bytes()
    with gzip.open(out1) as f:
        assert json.load(f)["functions"]["CreateFileW"][0]["ret"] == "h"


def test_main_reports_missing_submodule(gen: ModuleType, tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="git submodule update"):
        gen.generate(str(tmp_path / "empty"), str(OVERRIDES))


def test_overrides_file_is_well_formed(gen: ModuleType) -> None:
    overrides = gen.load_overrides(str(OVERRIDES))
    assert "wsprintfA" in overrides["variadic"]
    assert "icu" in overrides["cdecl_dlls"]
    assert overrides["dll_aliases"]["psapi"] == "kernel32"
    for key in ("cdecl_dlls", "cdecl", "variadic", "skip"):
        assert all(isinstance(v, str) for v in overrides[key])
    assert "GENERIC_READ" in overrides["enum_extra"]["FILE_ACCESS_FLAGS"]
