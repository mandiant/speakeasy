"""
Build hooks for speakeasy.

All project metadata lives in ``pyproject.toml``; this file only exists to
regenerate the Win32 API signature database from the ``deps/win32json``
submodule whenever a wheel or sdist is built, so that the generated
``speakeasy/resources/win32/signatures.json.gz`` ships in every distribution
without being committed to the repository.
"""

import os
import subprocess
import sys

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

HERE = os.path.dirname(os.path.abspath(__file__))
GENERATOR = os.path.join(HERE, "scripts", "gen_win32_signatures.py")
WIN32JSON = os.path.join(HERE, "deps", "win32json", "api")
OUTPUT = os.path.join(HERE, "speakeasy", "resources", "win32", "signatures.json.gz")


class build_py(_build_py):
    """Regenerate the signature database before collecting package data."""

    def run(self):
        self.generate_signatures()
        super().run()

    def generate_signatures(self):
        if not os.path.isdir(WIN32JSON):
            if os.path.exists(OUTPUT):
                self.announce(
                    f"deps/win32json missing; reusing existing {os.path.relpath(OUTPUT, HERE)}",
                    level=2,
                )
                return
            raise SystemExit(
                "deps/win32json is not checked out and no signature database exists; "
                "run `git submodule update --init deps/win32json` before building"
            )
        self.announce("generating Win32 API signature database from deps/win32json", level=2)
        subprocess.check_call([sys.executable, GENERATOR, "--output", OUTPUT])


setup(cmdclass={"build_py": build_py})
