"""Each upper-case int constant of speakeasy has one definition, so two copies cannot get different values."""

import ast
from collections import defaultdict
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "speakeasy"

# Names with more than one definition today. Remove a name when its copies become one.
ALLOWED = {
    "DISASM_SIZE",
    "ERROR_INSUFFICIENT_BUFFER",
    "ERROR_INVALID_HANDLE",
    "ERROR_MORE_DATA",
    "EXCEPTION_CONTINUE_EXECUTION",
    "EXCEPTION_CONTINUE_SEARCH",
    "EXCEPTION_EXECUTE_HANDLER",
    "E_INVALIDARG",
    "E_POINTER",
    "FILE_ATTRIBUTE_DIRECTORY",
    "FILE_ATTRIBUTE_NORMAL",
    "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE",
    "HKEY_USERS",
    "HOST_NOT_FOUND",
    "LOCALE_SYSTEM_DEFAULT",
    "LOCALE_USER_DEFAULT",
    "MAX_EXPORTS_TO_EMULATE",
    "MAX_PATH",
    "PAGE_SIZE",
    "PERF_FREQUENCY",
    "SIGFPE",
    "SIGILL",
    "SIGSEGV",
    "STATUS_ILLEGAL_INSTRUCTION",
    "STATUS_PRIVILEGED_INSTRUCTION",
    "S_FALSE",
    "S_OK",
    "WAIT_OBJECT_0",
    "WSADESCRIPTION_LEN",
    "WSAENOTSOCK",
    "WSASYS_STATUS_LEN",
    "X86_REG_CS",
    "X86_REG_DS",
}


def is_int_expression(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return type(node.value) is int
    if isinstance(node, ast.UnaryOp):
        return is_int_expression(node.operand)
    if isinstance(node, ast.BinOp):
        return is_int_expression(node.left) and is_int_expression(node.right)
    return isinstance(node, ast.Name) and node.id.isupper()


def get_duplicate_constants(package: Path) -> dict[str, list[str]]:
    locations = defaultdict(list)
    for path in sorted(package.rglob("*.py")):
        for statement in ast.parse(path.read_text(encoding="utf-8")).body:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                continue
            target = statement.targets[0]
            if isinstance(target, ast.Name) and target.id.isupper() and is_int_expression(statement.value):
                locations[target.id].append(f"{path.relative_to(package.parent)}:{statement.lineno}")
    return {name: places for name, places in locations.items() if len(places) > 1}


def test_constants_have_one_definition() -> None:
    duplicates = get_duplicate_constants(PACKAGE)
    assert {name: duplicates[name] for name in duplicates.keys() - ALLOWED} == {}
    assert ALLOWED - duplicates.keys() == set()
