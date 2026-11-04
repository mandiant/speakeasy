"""The ``--volume`` option: add host files to the emulated file system, as Docker volumes do."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath


def parse_volume_spec(spec: str) -> tuple[Path, PureWindowsPath]:
    r"""
    Parse a ``host_path:guest_path`` volume specification.

    Each path can start with a Windows drive letter, for example ``C:\samples:C:\guest``. The
    separator is the first ``:`` after the drive letter of the host path.

    Raises:
        ValueError: if the specification is empty or malformed.
    """
    if not spec:
        raise ValueError("Empty volume specification")

    start = 0
    if len(spec) >= 2 and spec[1] == ":":
        start = 2

    idx = spec.find(":", start)
    if idx == -1:
        raise ValueError(f"Invalid volume spec (missing ':' separator): {spec!r}")

    host_str = spec[:idx]
    guest_str = spec[idx + 1 :]

    if not host_str:
        raise ValueError(f"Empty host path in volume spec: {spec!r}")
    if not guest_str:
        raise ValueError(f"Empty guest path in volume spec: {spec!r}")

    return Path(host_str), PureWindowsPath(guest_str)


def expand_volume_to_entries(host_path: Path, guest_path: PureWindowsPath) -> list[dict]:
    """
    Expand a volume mapping into ``FileEntryFullPath``-compatible dicts.

    If ``host_path`` is a file, this returns one entry. If it is a
    directory, every file underneath it (recursively) becomes an entry
    with the relative path appended to ``guest_path``.

    Raises:
        FileNotFoundError: if ``host_path`` does not exist.
    """
    host_path = host_path.resolve()

    if not host_path.exists():
        raise FileNotFoundError(f"Volume host path does not exist: {host_path}")

    entries: list[dict] = []

    if host_path.is_file():
        entries.append(
            {
                "mode": "full_path",
                "emu_path": str(guest_path),
                "path": str(host_path),
            }
        )
    elif host_path.is_dir():
        for child in sorted(host_path.rglob("*")):
            if not child.is_file():
                continue
            rel = child.relative_to(host_path)
            emu_path = guest_path / PureWindowsPath(*rel.parts)
            entries.append(
                {
                    "mode": "full_path",
                    "emu_path": str(emu_path),
                    "path": str(child),
                }
            )

    return entries


def apply_volumes(config: dict, volume_specs: list[str]) -> dict:
    """
    Parse ``volume_specs`` and put the file entries before the file entries of ``config``.

    ``FileManager.get_emu_file`` uses the first ``full_path`` entry that matches, so the volume
    entries come first.

    Raises:
        ValueError: if a specification is empty or malformed.
        FileNotFoundError: if a host path does not exist.
    """
    if not volume_specs:
        return config

    new_entries: list[dict] = []
    for spec in volume_specs:
        host_path, guest_path = parse_volume_spec(spec)
        new_entries.extend(expand_volume_to_entries(host_path, guest_path))

    fs = config.setdefault("filesystem", {})
    existing = fs.get("files", [])
    fs["files"] = new_entries + existing

    return config
