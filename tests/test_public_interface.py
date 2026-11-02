import subprocess
import sys


def test_star_import_gives_every_public_name():
    # Import in a fresh interpreter, so that an import cycle between the package and its modules fails the test.
    # The star import raises AttributeError for a name in __all__ that the package does not define.
    result = subprocess.run([sys.executable, "-c", "from speakeasy import *"], capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
