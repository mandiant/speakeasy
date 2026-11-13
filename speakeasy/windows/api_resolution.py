"""
The results of the search for the code to run for an API call.

The code is a handler, a user hook, a function from the signature database, a stub, or
nothing. This module also has the related names of an API whose handler can run for it.
"""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from speakeasy import common
from speakeasy.windows.common import get_dll_hosts
from speakeasy.winenv.api import sigdb
from speakeasy.winenv.api.api import ApiHandler


@dataclass(frozen=True)
class HandlerImplementation:
    """
    The API has a handler.

    For an import by ordinal, ``name`` is the handler name. Otherwise it is the name
    that the guest called.
    """

    module: ApiHandler
    name: str
    func: Callable[..., Any]
    argc: int
    conv: int


@dataclass(frozen=True)
class UserHookImplementation:
    """
    Speakeasy has no handler for the API, but the user added hooks for it.

    The user adds hooks with ``add_api_hook``. The module and API names of a hook can
    have wildcards, so one hook can match many APIs. The hook takes the place of the
    handler: it gives the argument count and the calling convention, and the emulator
    gives its return value to the guest. The emulator runs only the hook that the user
    added last, because there is no handler for the hooks to call, and the hooks can
    give different argument counts.

    If the API has a handler, the result is ``HandlerImplementation``, and each hook
    for the API can call the handler.
    """

    hooks: list[common.ApiHook]


@dataclass(frozen=True)
class SignatureImplementation:
    """
    The API has no handler, but it is in the signature database.

    The declaration gives the arguments to log and the stack to clean up.
    """

    sig: sigdb.FuncSig


@dataclass(frozen=True)
class StubImplementation:
    """The API is not known, and ``apis.stubs`` is set."""


@dataclass(frozen=True)
class UnsupportedImplementation:
    """The API is not known."""


ApiImplementation = (
    HandlerImplementation
    | UserHookImplementation
    | SignatureImplementation
    | StubImplementation
    | UnsupportedImplementation
)


def _get_nt_zw_alias(name: str) -> str:
    if name.startswith("Zw"):
        return f"Nt{name[2:]}"
    if name.startswith("Nt"):
        return f"Zw{name[2:]}"
    return ""


def get_handler_candidates(dll: str, name: str) -> Iterator[tuple[str, str]]:
    """
    Yield other (dll, name) pairs whose handler can run for dll!name, best first.

    For example: the name without the A or W suffix, the Zw name for an Nt name, or
    the modules that implement an API set.
    """
    seen = {(dll.lower(), name)}
    for cand_dll, cand_name in _get_aliases(dll, name):
        key = (cand_dll.lower(), cand_name)
        if key not in seen:
            seen.add(key)
            yield cand_dll, cand_name


def _get_aliases(dll: str, name: str) -> Iterator[tuple[str, str]]:
    alias = ""
    # One handler without the suffix can serve the A and the W variant
    if name.endswith(("A", "W")):
        alias = name[:-1]

    # The private CRT exports _o_ copies of public CRT functions
    if name.startswith("_o_"):
        alias = name[3:]

    # ntdll uses the ntoskrnl handler of an API, if one exists
    if dll.lower().startswith("ntdll"):
        yield "ntoskrnl", name
        nt_alias = _get_nt_zw_alias(name) or alias
        if nt_alias:
            yield "ntoskrnl", nt_alias
        # ntdll also exports a subset of the C runtime
        yield "msvcrt", name
        return

    # One ntoskrnl handler serves both the Nt and the Zw name
    if dll.lower().startswith("ntoskrnl"):
        alias = _get_nt_zw_alias(name) or alias

    if alias:
        yield dll, alias
    for host in get_dll_hosts(dll):
        yield host, name
        if alias:
            yield host, alias
        if host.lower() == "kernel32":
            if name.startswith("Reg"):
                yield "advapi32", name
                if alias:
                    yield "advapi32", alias
            elif name.startswith("K32"):
                for func in (name[3:], alias[3:]):
                    if func:
                        yield "psapi", func
