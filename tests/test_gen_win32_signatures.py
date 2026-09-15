"""Tests for scripts/gen_win32_signatures.py using a miniature win32json tree."""

import gzip
import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "scripts" / "gen_win32_signatures.py"
OVERRIDES = REPO_ROOT / "scripts" / "win32_overrides.json"


@pytest.fixture(scope="module")
def gen():
    spec = importlib.util.spec_from_file_location("gen_win32_signatures", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _native(name):
    return {"Kind": "Native", "Name": name}


def _ref(api, name, target="Default"):
    return {"Kind": "ApiRef", "Name": name, "TargetKind": target, "Api": api, "Parents": []}


def _ptr(child):
    return {"Kind": "PointerTo", "Child": child}


def _typedef(name, definition, **extra):
    td = {
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


def _struct(name, fields, kind="Struct", packing=0):
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


def _func(name, dll, ret, params, **extra):
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
def mini_win32json(tmp_path):
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
            {
                "Name": "FLAGS",
                "Architectures": [],
                "Platform": None,
                "Kind": "Enum",
                "Flags": True,
                "Scoped": False,
                "IntegerBase": "UInt32",
                "Values": [{"Name": "A", "Value": 1}],
            },
        ],
    }
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


def test_generate_resolves_types(gen, mini_win32json):
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
        ["dwFlags", "u32", "i"],
        ["hTemplateFile", "h", "i?"],
        ["hwnd", "h", "i"],
        ["lParam", "p", "i"],
        ["ok", "b", "i"],
        ["okay", "B", "i"],
        ["cb", "p", "i"],
        ["pUnk", "p", "i"],
        ["ppOut", "p", "o"],
        ["buffer", "p", "o"],
        ["name", "s", "o"],
    ]


def test_generate_by_value_struct_sizes(gen, mini_win32json):
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


def test_generate_applies_overrides(gen, mini_win32json):
    doc, stats = gen.generate(str(mini_win32json), str(OVERRIDES))
    (ws,) = doc["functions"]["wsprintfA"]
    assert ws["variadic"] is True and ws["conv"] == "cdecl"
    (ldap,) = doc["functions"]["ldap_bind_sA"]
    assert ldap["conv"] == "cdecl"
    assert stats["variadic"] == 1
    assert stats["cdecl"] == 2


def test_generate_arch_skip_and_duplicates(gen, mini_win32json):
    doc, stats = gen.generate(str(mini_win32json), str(OVERRIDES))
    (x86,) = doc["functions"]["OnlyX86"]
    assert x86["arch"] == ["x86"]

    (unknown,) = doc["functions"]["Unknown"]
    assert unknown["skip"].startswith("param x: unknown type Nowhere.MISSING_TYPE")
    assert stats["skipped"] == 1

    dups = doc["functions"]["Dup"]
    assert [d["dll"] for d in dups] == ["a", "b"]
    assert stats["duplicates"] == 1


def test_write_output_is_reproducible(gen, mini_win32json, tmp_path):
    doc, _ = gen.generate(str(mini_win32json), str(OVERRIDES))
    out1 = tmp_path / "a.json.gz"
    out2 = tmp_path / "b.json.gz"
    gen.write_output(doc, str(out1))
    gen.write_output(doc, str(out2))
    assert out1.read_bytes() == out2.read_bytes()
    with gzip.open(out1) as f:
        assert json.load(f)["functions"]["CreateFileW"][0]["ret"] == "h"


def test_main_reports_missing_submodule(gen, tmp_path):
    with pytest.raises(SystemExit, match="git submodule update"):
        gen.generate(str(tmp_path / "empty"), str(OVERRIDES))


def test_overrides_file_is_well_formed(gen):
    overrides = gen.load_overrides(str(OVERRIDES))
    assert "wsprintfA" in overrides["variadic"]
    assert "icu" in overrides["cdecl_dlls"]
    assert overrides["dll_aliases"]["psapi"] == "kernel32"
    for key in ("cdecl_dlls", "cdecl", "variadic", "skip"):
        assert all(isinstance(v, str) for v in overrides[key])
