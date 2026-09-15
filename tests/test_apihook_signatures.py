"""
Cross-check every hand-written ``@apihook`` declaration against the Win32 API
signature database. A mismatch in ``argc`` corrupts the emulated stack on x86,
so hooks and metadata must agree wherever both exist.
"""

from collections.abc import Iterator

import pytest

import speakeasy.winenv.arch as _arch
from speakeasy.winenv.api import sigdb, winapi

# Hooks whose argc intentionally differs from the documented prototype.
# Add an entry with a justification if a deviation is deliberate.
KNOWN_DEVIATIONS: dict[tuple[str, str], str] = {}


def _hooked_functions() -> Iterator[tuple[str, str, int, int]]:
    for mod_name, cls in winapi.API_HANDLERS:
        for attr in dir(cls):
            func = getattr(cls, attr, None)
            hook = getattr(func, "__apihook__", None)
            if hook:
                name, _, argc, conv, ordinal = hook
                if isinstance(name, str) and not name.startswith("ordinal_"):
                    yield mod_name, name, argc, conv


def _lookup(db: sigdb.SignatureDatabase, mod_name: str, name: str) -> sigdb.FuncSig | None:
    for candidate in (name, name + "W", name + "A"):
        sig = db.lookup(mod_name, candidate, sigdb.ARCH_X86)
        if sig is not None:
            return sig
    return None


def test_apihook_argc_matches_metadata() -> None:
    db = sigdb.get_default_database()
    if not db.available:
        pytest.skip("bundled signature database not generated (run scripts/gen_win32_signatures.py)")

    compared = 0
    mismatches = []
    for mod_name, name, argc, conv in _hooked_functions():
        if conv != _arch.CALL_CONV_STDCALL:
            continue
        sig = _lookup(db, mod_name, name)
        if sig is None or sig.skip or sig.variadic or sig.conv != sigdb.CONV_STDCALL:
            continue
        # win32metadata implements the same prototype under a different DLL for
        # forwarders; only compare when the hook module owns the declaration.
        if sig.dll != mod_name.lower():
            continue
        compared += 1
        expected = sig.slot_count(4)
        if expected != argc and (mod_name, name) not in KNOWN_DEVIATIONS:
            mismatches.append(f"{mod_name}.{name}: hook argc={argc}, metadata argc={expected}")

    assert compared > 500, "expected the metadata to cover most hooks"
    assert not mismatches, "\n".join(mismatches)
