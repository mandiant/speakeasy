"""
Check the ``ctx.args[...]`` accesses in ``@apihook`` handlers against the
signature database. A name only finds its argument when the call has a usable
signature, so a handler may use names only when every signature of the
function it serves declares that parameter and matches its ``argc`` on x86 and
x64. An index means the parameter index with a signature and the slot index
without one, so a handler may use an index only where both agree.
"""

import ast
import inspect
import textwrap
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from speakeasy.windows import common as winemu
from speakeasy.winenv.api import sigdb, winapi

PTR_SIZES = {sigdb.ARCH_X86: 4, sigdb.ARCH_X64: 8}


@dataclass(frozen=True)
class ArgAccess:
    mod_name: str
    name: str
    argc: int
    key: int | str


def _get_accesses() -> Iterator[ArgAccess]:
    for mod_name, cls in winapi.API_HANDLERS:
        for attr in dir(cls):
            func = getattr(cls, attr, None)
            hook = getattr(func, "__apihook__", None)
            if not hook or not isinstance(hook[0], str):
                continue
            name, handler, argc, _, _ = hook
            tree = ast.parse(textwrap.dedent(inspect.getsource(handler)))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Subscript)
                    and isinstance(node.value, ast.Attribute)
                    and node.value.attr == "args"
                    and isinstance(node.value.value, ast.Name)
                    and node.value.value.id == "ctx"
                    and isinstance(node.slice, ast.Constant)
                    and isinstance(node.slice.value, (int, str))
                ):
                    yield ArgAccess(mod_name, name, argc, node.slice.value)


def _get_signatures(db: sigdb.SignatureDatabase, access: ArgAccess, arch: str) -> list[sigdb.FuncSig]:
    """Signatures of the imports that ``handle_import_func`` sends to the handler."""
    names = {access.name, access.name + "A", access.name + "W"}
    if access.mod_name.lower() == "ntoskrnl" and access.name[:2] in ("Nt", "Zw"):
        names |= {"Nt" + access.name[2:], "Zw" + access.name[2:]}
    dlls = {access.mod_name, winemu.normalize_dll_name(access.mod_name)}
    sigs = [db.lookup(dll, name, arch) for dll in dlls for name in sorted(names)]
    return [sig for sig in sigs if sig is not None and not sig.skip]


def _usable(sig: sigdb.FuncSig, arch: str, argc: int) -> bool:
    return not sig.variadic and sig.slot_count(PTR_SIZES[arch]) == argc


def test_handler_arg_access_matches_signatures() -> None:
    db = sigdb.get_default_database()
    if not db.available:
        pytest.skip("bundled signature database not generated (run scripts/gen_win32_signatures.py)")

    problems = []
    for access in _get_accesses():
        where = f"{access.mod_name}.{access.name}: ctx.args[{access.key!r}]"
        sigs = {arch: _get_signatures(db, access, arch) for arch in PTR_SIZES}
        if isinstance(access.key, str):
            if not any(sigs.values()):
                problems.append(f"{where}: no signature")
            for arch, arch_sigs in sigs.items():
                for sig in arch_sigs:
                    if not _usable(sig, arch, access.argc):
                        problems.append(f"{where}: {sig.dll}.{sig.name} does not match argc on {arch}")
                    elif access.key not in [p.name for p in sig.params]:
                        problems.append(f"{where}: {sig.dll}.{sig.name} has no such parameter")
            continue
        if access.key < 0:
            problems.append(f"{where}: negative index")
            continue
        for arch, arch_sigs in sigs.items():
            for sig in arch_sigs:
                if _usable(sig, arch, access.argc) and sum(sig.slot_layout(PTR_SIZES[arch])[: access.key]) != (
                    access.key
                ):
                    problems.append(f"{where}: parameter and slot index differ in {sig.name} on {arch}")

    assert not problems, "\n".join(problems)
