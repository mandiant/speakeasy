"""
Build hooks for speakeasy.

All project metadata lives in ``pyproject.toml``; this file only exists to
regenerate the API signature databases from the ``deps/win32json`` and
``deps/phnt`` submodules whenever a wheel or sdist is built, so that the
generated ``speakeasy/resources/win32/*.json.gz`` files ship in every
distribution without being committed to the repository.
"""

import os
import subprocess
import sys

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist

HERE = os.path.dirname(os.path.abspath(__file__))
RESOURCES = os.path.join(HERE, "speakeasy", "resources", "win32")

# (generator script, submodule marker path, output file)
DATABASES = [
    (
        os.path.join(HERE, "scripts", "gen_win32_signatures.py"),
        os.path.join(HERE, "deps", "win32json", "api"),
        os.path.join(RESOURCES, "signatures.json.gz"),
    ),
    (
        os.path.join(HERE, "scripts", "gen_phnt_signatures.py"),
        os.path.join(HERE, "deps", "phnt", "ntpsapi.h"),
        os.path.join(RESOURCES, "phnt_signatures.json.gz"),
    ),
]


def _generate_signatures(announce=None):
    for generator, marker, output in DATABASES:
        submodule = os.path.relpath(os.path.dirname(marker) if marker.endswith(".h") else marker, HERE)
        submodule = submodule.split(os.sep + "api")[0]
        if not os.path.exists(marker):
            if os.path.exists(output):
                if announce:
                    announce(f"{submodule} missing; reusing existing {os.path.relpath(output, HERE)}", level=2)
                continue
            raise SystemExit(
                f"{submodule} is not checked out and no signature database exists; "
                f"run `git submodule update --init {submodule}` before building"
            )
        if announce:
            announce(f"generating API signature database from {submodule}", level=2)
        subprocess.check_call([sys.executable, generator, "--output", output])


class build_py(_build_py):
    """Regenerate the signature database before collecting package data."""

    def run(self) -> None:
        _generate_signatures(self.announce)
        super().run()


class sdist(_sdist):
    """Regenerate the signature database so the generated files are included in the sdist."""

    def run(self) -> None:
        _generate_signatures(self.announce)
        super().run()


setup(cmdclass={"build_py": build_py, "sdist": sdist})
