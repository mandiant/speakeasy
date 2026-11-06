#!/usr/bin/env python3
"""
Generate the lists of the DLL names in System32 and SysWOW64 of a clean Windows install.

The source is winbindex (https://winbindex.m417z.com, https://github.com/m417z/winbindex).
For each release, winbindex records the files of the install image of the release ISO
(the ``BASE`` entry of the release, with the ISO SHA-256 and the paths of each file in
the image). This script downloads the winbindex record of each DLL name and keeps the
names that the install image of the release has in ``Windows/System32`` (x64) or in
``Windows/SysWOW64`` (x86).

The outputs are ``speakeasy/resources/win32/system_dlls/x64.txt`` and ``x86.txt``:
lower-case file names, sorted, one name on each line. See the README.md in that directory.

Usage::

    python scripts/gen_system_dlls.py [--release 11-24H2] [--cache DIR] [--output DIR]
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "speakeasy" / "resources" / "win32" / "system_dlls"
DEFAULT_RELEASE = "11-24H2"
WINBINDEX_DATA = "https://winbindex.m417z.com/data/"
DIRECTORIES = {"x64": "windows\\system32\\", "x86": "windows\\syswow64\\"}


def download(url: str, path: Path, attempts: int = 6) -> Path:
    """
    Download url to path, unless path exists.

    Raises:
        urllib.error.URLError: the last attempt fails.
    """
    if path.exists():
        return path
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read()
            break
        except urllib.error.HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504) or attempt == attempts - 1:
                raise
        except urllib.error.URLError:
            if attempt == attempts - 1:
                raise
        time.sleep(2**attempt)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)
    return path


def get_dll_names(cache: Path) -> list[str]:
    path = download(WINBINDEX_DATA + "filenames.json", cache / "filenames.json")
    names = json.loads(path.read_text())
    return sorted({name.lower() for name in names if name.lower().endswith(".dll")})


def get_record(name: str, cache: Path) -> dict:
    url = WINBINDEX_DATA + "by_filename_compressed/" + urllib.parse.quote(name) + ".json.gz"
    path = download(url, cache / "by_filename_compressed" / (name + ".json.gz"))
    with gzip.open(path) as f:
        return json.load(f)


def get_directories(name: str, record: dict, release: str) -> tuple[set[str], set[str]]:
    """
    Get the architectures whose system directory has the file in the install image of release.

    Also get the ISO SHA-256 values of the release that the record names.
    """
    archs: set[str] = set()
    isos: set[str] = set()
    for entry in record.values():
        base = entry.get("windowsVersions", {}).get(release, {}).get("BASE")
        if base is None:
            continue
        isos.add(base["windowsVersionInfo"]["isoSha256"])
        for source_path in base.get("sourcePaths", []):
            for arch, directory in DIRECTORIES.items():
                if source_path.lower() == directory + name:
                    archs.add(arch)
    return archs, isos


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--release", default=DEFAULT_RELEASE, help="winbindex release key, such as 11-24H2 or 22H2")
    ap.add_argument("--cache", type=Path, default=Path("/tmp/winbindex"), help="directory for the downloads")
    ap.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="directory for x64.txt and x86.txt")
    ap.add_argument("--jobs", type=int, default=8, help="number of parallel downloads")
    args = ap.parse_args(argv)

    (args.cache / "by_filename_compressed").mkdir(parents=True, exist_ok=True)
    names = get_dll_names(args.cache)
    print(f"{len(names)} DLL names in winbindex", file=sys.stderr)

    lists: dict[str, list[str]] = {arch: [] for arch in DIRECTORIES}
    isos: set[str] = set()
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        records = pool.map(lambda n: get_record(n, args.cache), names)
        for name, record in zip(names, records, strict=True):
            archs, record_isos = get_directories(name, record, args.release)
            isos |= record_isos
            for arch in archs:
                lists[arch].append(name)

    if len(isos) != 1:
        raise SystemExit(f"error: expected one ISO for release {args.release}, found {sorted(isos)}")
    args.output.mkdir(parents=True, exist_ok=True)
    for arch, arch_names in lists.items():
        path = args.output / f"{arch}.txt"
        path.write_text("".join(n + "\n" for n in sorted(arch_names)))
        print(f"wrote {path}: {len(arch_names)} names", file=sys.stderr)
    print(f"release {args.release}, ISO SHA-256 {isos.pop()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
