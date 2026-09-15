"""Tests for scripts/gen_phnt_signatures.py using a miniature phnt header set."""

import gzip
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "scripts" / "gen_phnt_signatures.py"

HEADER = r"""
/*
 * comment with a fake prototype:
 * NTSYSAPI VOID NTAPI NotReal(VOID);
 */
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _TEB* PTEB;
typedef ULONG_PTR KAFFINITY, *PKAFFINITY;
typedef NTSTATUS (NTAPI *PIO_APC_ROUTINE)(
    _In_ PVOID ApcContext
    );

typedef enum _KEY_INFORMATION_CLASS
{
    KeyBasicInformation, // KEY_BASIC_INFORMATION
    KeyNodeInformation,
    KeyFullInformation = 5,
    KeyFlags = 1 << 3,
    KeyCombined = KeyFullInformation | KeyFlags,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef enum _FLAGGY
{
    FlagA = 0x1,
    FlagB = 0x2,
    FlagC = 0x4,
} FLAGGY, *PFLAGGY;

#if (PHNT_VERSION >= PHNT_WINDOWS_10)
/**
 * Creates a file.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength
    );
#endif

NTSYSAPI
_Success_(return != 0)
LOGICAL
NTAPI
RtlQueryKey(
    _In_ HANDLE KeyHandle,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength,
    _Inout_ PKAFFINITY Affinity,
    _In_reads_(Count) HANDLE Handles[],
    _In_ ULONG Count,
    _In_ FLAGGY Flags,
    _Out_ PTEB *Teb,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _Reserved_ PVOID Reserved
    );

NTSYSAPI
ULONG
STDAPIVCALLTYPE
DbgPrint(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    );

NTSYSAPI
VOID
NTAPI
RtlNoArgs(
    VOID
    );

FORCEINLINE
VOID
NTAPI
RtlInlineHelper(
    _In_ ULONG X
    )
{
    return;
}

NTSYSAPI
NTSTATUS
NTAPI
RtlUsesUnknownType(
    _In_ MYSTERY_T Value
    );

NTSYSAPI
UNICODE_STRING
NTAPI
RtlReturnsStructByValue(
    _In_ ULONG X
    );

// callback typedef, not an export
typedef VOID (NTAPI *PCALLBACK)(
    _In_ ULONG Value
    );
"""


@pytest.fixture(scope="module")
def gen() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_phnt_signatures", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def mini_phnt(tmp_path: Path) -> Path:
    root = tmp_path / "phnt"
    root.mkdir()
    (root / "ntmini.h").write_text(HEADER.replace("\n", "\r\n"), newline="")
    (root / "phnt.h").write_text("#include <ntmini.h>\r\n", newline="")
    return root


def test_generate_prototypes(gen: ModuleType, mini_phnt: Path) -> None:
    doc, stats = gen.generate(str(mini_phnt))
    assert doc["format"] == gen.FORMAT_VERSION
    assert doc["source"] == "phnt"
    assert doc["structs"] == {}
    funcs = doc["functions"]
    assert set(funcs) == {
        "NtCreateFile",
        "RtlQueryKey",
        "DbgPrint",
        "RtlNoArgs",
        "RtlUsesUnknownType",
        "RtlReturnsStructByValue",
    }

    (cf,) = funcs["NtCreateFile"]
    assert cf == {
        "dll": "ntdll",
        "ret": "i32",
        "params": [
            ["FileHandle", "p:h", "o"],
            ["DesiredAccess", "u32", "i"],
            ["ObjectAttributes", "ps:OBJECT_ATTRIBUTES", "i"],
            ["AllocationSize", "ps:LARGE_INTEGER", "i?"],
            ["EaBuffer", "p", "i?", {"n": 5}],
            ["EaLength", "u32", "i"],
        ],
    }

    (qk,) = funcs["RtlQueryKey"]
    assert qk["ret"] == "u32"  # _Success_ annotation on the return type is ignored
    assert qk["params"] == [
        ["KeyHandle", "h", "i"],
        ["KeyInformationClass", "i32:KEY_INFORMATION_CLASS", "i"],
        ["KeyInformation", "p", "o?", {"n": 3}],
        ["Length", "u32", "i"],
        ["ResultLength", "p:u32", "o"],
        ["Affinity", "p:p", "io"],
        ["Handles", "p:h", "i", {"c": 7}],
        ["Count", "u32", "i"],
        ["Flags", "i32:FLAGGY", "i"],
        ["Teb", "p:ps:TEB", "o"],
        ["ApcRoutine", "p", "i?"],
        ["Reserved", "p", "r"],
    ]
    assert "conv" not in qk and "skip" not in qk

    (dbg,) = funcs["DbgPrint"]
    assert dbg["variadic"] is True and dbg["conv"] == "cdecl"
    assert dbg["params"] == [["Format", "s", "i"]]

    (noargs,) = funcs["RtlNoArgs"]
    assert noargs["ret"] == "v" and noargs["params"] == []

    (unknown,) = funcs["RtlUsesUnknownType"]
    # ALL_CAPS names are assumed to be SDK structs; by value their size is unknown, so skip
    assert unknown["skip"] == "param Value: by-value struct MYSTERY_T of unknown size"
    (by_value,) = funcs["RtlReturnsStructByValue"]
    assert by_value["ret"] == "st:UNICODE_STRING:8/16"

    assert stats["functions"] == 6 and stats["supported"] == 5 and stats["skipped"] == 1
    assert stats["variadic"] == 1


def test_generate_enums(gen: ModuleType, mini_phnt: Path) -> None:
    doc, _ = gen.generate(str(mini_phnt))
    assert doc["enums"]["KEY_INFORMATION_CLASS"] == {
        "v": [
            ["KeyBasicInformation", 0],
            ["KeyNodeInformation", 1],
            ["KeyFullInformation", 5],
            ["KeyFlags", 8],
            ["KeyCombined", 13],
            ["MaxKeyInfoClass", 14],
        ]
    }
    # all members powers of two: treated as flags
    assert doc["enums"]["FLAGGY"] == {"v": [["FlagA", 1], ["FlagB", 2], ["FlagC", 4]], "f": True}


def test_eval_const(gen: ModuleType) -> None:
    assert gen.eval_const("0x10 | (1 << 2)", {}) == 0x14
    assert gen.eval_const("A + 1", {"A": 41}) == 42
    assert gen.eval_const("~0", {}) == -1
    assert gen.eval_const("2UL", {}) == 2
    with pytest.raises(ValueError):
        gen.eval_const("sizeof(ULONG)", {})
    with pytest.raises(ValueError):
        gen.eval_const("Missing", {})


def test_type_resolution(gen: ModuleType, mini_phnt: Path) -> None:
    headers = gen.load_headers(str(mini_phnt))
    types = gen.TypeTable()
    for text in headers.values():
        types.collect(text)
    assert types.resolve("PUNICODE_STRING") == "ps:UNICODE_STRING"
    assert types.resolve("PCUNICODE_STRING") == "ps:UNICODE_STRING"
    assert types.resolve("const UNICODE_STRING *") == "ps:UNICODE_STRING"
    assert types.resolve("UNICODE_STRING **") == "p:ps:UNICODE_STRING"
    assert types.resolve("KAFFINITY") == "p"
    assert types.resolve("PKAFFINITY") == "p:p"
    assert types.resolve("PTEB") == "ps:TEB"
    assert types.resolve("PIO_APC_ROUTINE") == "p"
    assert types.resolve("PCALLBACK") == "p"
    assert types.resolve("PWSTR") == "S"
    assert types.resolve("WCHAR *") == "S"
    assert types.resolve("CHAR *") == "s"
    assert types.resolve("PVOID *") == "p:p"
    assert types.resolve("unsigned long") == "u32"
    assert types.resolve("PSOME_SDK_STRUCT") == "ps:SOME_SDK_STRUCT"
    assert types.resolve("SECURITY_INFORMATION") == "u32"
    with pytest.raises(gen.UnsupportedType):
        types.resolve("Mystery")


def test_write_output_is_reproducible(gen: ModuleType, mini_phnt: Path, tmp_path: Path) -> None:
    doc, _ = gen.generate(str(mini_phnt))
    out1 = tmp_path / "a.json.gz"
    out2 = tmp_path / "b.json.gz"
    gen.write_output(doc, str(out1))
    gen.write_output(doc, str(out2))
    assert out1.read_bytes() == out2.read_bytes()
    with gzip.open(out1) as f:
        assert json.load(f)["functions"]["DbgPrint"][0]["variadic"] is True


def test_main_reports_missing_submodule(gen: ModuleType, tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="git submodule update"):
        gen.generate(str(tmp_path / "empty"))
