"""
Find the related names of an API whose handler can run for it.
"""

from collections.abc import Iterator

from speakeasy.windows.common import normalize_dll_name


def _get_nt_zw_alias(name: str) -> str:
    if name.startswith("Zw"):
        return f"Nt{name[2:]}"
    if name.startswith("Nt"):
        return f"Zw{name[2:]}"
    return ""


def get_handler_candidates(dll: str, name: str) -> Iterator[tuple[str, str]]:
    """
    Yield other (dll, name) pairs whose handler can run for dll!name, best first.
    For example: the name without the A or W suffix, the name without the CRT
    "_o_" prefix, the Zw name for an Nt name, ntoskrnl and msvcrt for ntdll, the
    DLL that implements an API set, advapi32 for kernel32 Reg functions, and psapi
    for kernel32 K32 functions.
    """
    seen = {(dll.lower(), name)}
    for cand_dll, cand_name in _get_aliases(dll, name):
        key = (cand_dll.lower(), cand_name)
        if key not in seen:
            seen.add(key)
            yield cand_dll, cand_name


def _get_aliases(dll: str, name: str) -> Iterator[tuple[str, str]]:
    alias = ""
    # Handle ANSI vs UNICODE functions
    if name.endswith(("A", "W")):
        alias = name[:-1]

    # The private CRT exports _o_ copies of public CRT functions
    if name.startswith("_o_"):
        alias = name[3:]

    # Bridge ntdll funcs to ntoskrnl if supported
    if dll.lower().startswith("ntdll"):
        yield "ntoskrnl", name
        nt_alias = _get_nt_zw_alias(name) or alias
        if nt_alias:
            yield "ntoskrnl", nt_alias
        # ntdll also exports a subset of the C runtime
        yield "msvcrt", name
        return

    # Handle Zw*/Nt* function overlap
    if dll.lower().startswith("ntoskrnl"):
        alias = _get_nt_zw_alias(name) or alias

    alt_dll = normalize_dll_name(dll)
    if alias:
        yield dll, alias
    if alt_dll:
        yield alt_dll, name
        if alias:
            yield alt_dll, alias
    if alt_dll.lower() == "kernel32":
        if name.startswith("Reg"):
            yield "advapi32", name
            if alias:
                yield "advapi32", alias
        elif name.startswith("K32"):
            for func in (name[3:], alias[3:]):
                if func:
                    yield "psapi", func
