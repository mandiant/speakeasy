format:
    uvx ruff format

ruff:
    uvx ruff check --fix
    uvx ruff check --select I --fix

# lots of errors due to dynamic access to C structures
# address this later
# mypy:
#     uvx mypy --check-untyped-defs debugger speakeasy tests examples

lint: format ruff

test:
    ./.venv/bin/pytest -q tests/

test-pma:
    ./.venv/bin/pytest -q tests/test_pma_samples.py
