"""Each upper-case int constant of speakeasy has one definition, so two copies cannot get different values."""

import ast
from collections import defaultdict
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "speakeasy"

# Names with more than one definition today. Remove a name when its copies become one.
ALLOWED = {
    "DISASM_SIZE",
    "EXCEPTION_CONTINUE_EXECUTION",
    "EXCEPTION_CONTINUE_SEARCH",
    "EXCEPTION_EXECUTE_HANDLER",
    "MAX_EXPORTS_TO_EMULATE",
    "PAGE_SIZE",
    "SIGSEGV",
    "STATUS_ILLEGAL_INSTRUCTION",
    "STATUS_PRIVILEGED_INSTRUCTION",
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
