set quiet

# keep in sync with the ruff version in pyproject.toml and .github/workflows/test.yml
ruff := "uvx --quiet ruff@0.17.3"

# lint only tracked files, so that local files that are not in the repo stay as they are
format:
    git ls-files -z '*.py' | xargs -0 {{ruff}} format --quiet --force-exclude

ruff:
    git ls-files -z '*.py' | xargs -0 {{ruff}} check --quiet --fix --force-exclude
    git ls-files -z '*.py' | xargs -0 {{ruff}} check --quiet --select I --fix --force-exclude

mypy:
    ./.venv/bin/mypy speakeasy

lint: format ruff mypy

# regenerate the API signature databases from the deps/win32json and deps/phnt submodules
gen-signatures:
    git submodule update --init deps/win32json deps/phnt
    ./.venv/bin/python scripts/gen_win32_signatures.py --stats
    ./.venv/bin/python scripts/gen_phnt_signatures.py --stats

test:
    ./.venv/bin/pytest -x -q --no-header tests/

test-pma:
    ./.venv/bin/pytest -x -q --no-header tests/test_pma_samples.py
