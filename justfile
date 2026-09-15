set quiet

format:
    uvx --quiet ruff format --quiet

ruff:
    uvx --quiet ruff check --quiet --fix
    uvx --quiet ruff check --quiet --select I --fix

# lots of errors due to dynamic access to C structures
# address this later
# mypy:
#     uvx mypy --check-untyped-defs speakeasy tests examples

lint: format ruff

# regenerate the Win32 API signature database from the deps/win32json submodule
gen-signatures:
    git submodule update --init deps/win32json
    ./.venv/bin/python scripts/gen_win32_signatures.py --stats

test:
    ./.venv/bin/pytest -x -q --no-header tests/

test-pma:
    ./.venv/bin/pytest -x -q --no-header tests/test_pma_samples.py
