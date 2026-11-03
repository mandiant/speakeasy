# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import ctypes as ct
import fnmatch
import hashlib
import io
import logging
import ntpath
import os
import shlex
from typing import TYPE_CHECKING, Any

import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.config import FileEntry, FileEntryFullPath, FilesystemConfig, SpeakeasyConfig
from speakeasy.errors import FileSystemEmuError
from speakeasy.windows.handles import HandleTable

if TYPE_CHECKING:
    from speakeasy.windows.objman import Process

logger = logging.getLogger(__name__)

DIRECTORY_ENV_VARS = (
    "allusersprofile",
    "appdata",
    "commonprogramfiles",
    "localappdata",
    "path",
    "programdata",
    "programfiles",
    "public",
    "systemroot",
    "temp",
    "tmp",
    "userprofile",
    "windir",
)


NULL_DEVICE_PREFIXES = ("\\\\.\\", "\\??\\")


def is_null_device(path):
    for prefix in NULL_DEVICE_PREFIXES:
        if path.startswith(prefix):
            path = path[len(prefix) :]
            break
    return path.lower() == "nul"


def get_path_key(path):
    return ntpath.normpath(path).rstrip("\\").lower()


def normalize_response_path(path):
    def _get_speakeasy_root():
        return os.path.join(os.path.dirname(__file__), os.pardir)

    root_var = "$ROOT$"
    if root_var in path:
        root = _get_speakeasy_root()
        return path.replace(root_var, root)
    return path


class MapView:
    """Represents a shared memory view."""

    def __init__(self, base, offset, size, protect, process=None):
        self.base: int = base
        self.offset: int = offset
        self.size: int = size
        self.protect: int = protect
        self.process: Process | None = process


def get_object_name_key(name):
    name = name.lower()
    if "basenamedobjects\\" in name:
        name = name.split("basenamedobjects\\", 1)[1]
    for prefix in ("global\\", "local\\"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
    return name


class FileMap:
    """Represents a memory mapped file."""

    def __init__(self, name, size, prot, backed_file=None):
        self.name: str | None = name
        self.backed_file: File | None = backed_file
        self.views: dict[int, MapView] = {}
        self.size: int = size
        self.prot: int = prot

    def add_view(self, base, offset, size, protect):
        view = MapView(base, offset, size, protect)
        self.views.update({base: view})


class File:
    """Base class for an emulated file."""

    def __init__(self, path, config=None, data=b""):
        self.path: str = path
        self.data: io.BytesIO | None = None
        self.pos: int = 0
        self.origin: File | None = None
        self.bytes_written: int = 0
        if data:
            self.data = io.BytesIO(data)
        self.is_dir: bool = False
        self.append: bool = False
        self.config: FileEntry | dict[str, Any] = config if config is not None else {}

    def get_buffer(self) -> io.BytesIO:
        if self.data is None:
            self.data = self.handle_file_data() if self.config else io.BytesIO()
        return self.data

    def duplicate(self):
        """Get a new file object for another handle: it shares the contents and has its own position."""
        new = File(self.path, config=self.config)
        new.data = self.get_buffer()
        new.origin = self.origin or self
        new.is_dir = self.is_dir
        return new

    def get_hash(self):
        return hashlib.sha256(self.get_contents()).hexdigest()

    def get_size(self):
        return self.get_buffer().seek(0, io.SEEK_END)

    def get_data(self, size=-1, reset_pointer=False):
        buf = self.get_buffer()
        if self.pos == self.get_size():
            if not reset_pointer:
                return b""
            self.pos = 0
        buf.seek(self.pos)
        data = buf.read(size)
        self.pos = buf.tell()
        return data

    def get_contents(self):
        """Return all the file data and keep the file pointer."""
        return self.get_buffer().getvalue()

    def seek(self, offset, whence):
        if whence not in [io.SEEK_CUR, io.SEEK_SET, io.SEEK_END]:
            return
        buf = self.get_buffer()
        buf.seek(self.pos)
        self.pos = buf.seek(offset, whence)

    def tell(self):
        return self.pos

    def add_data(self, data):
        buf = self.get_buffer()
        buf.seek(0, io.SEEK_END)
        buf.write(data)
        self.bytes_written += len(data)
        if self.origin:
            self.origin.bytes_written += len(data)

    def write_data(self, data):
        """
        Write data at the file pointer, or at the end for an append-only handle.

        The file pointer moves past the data.
        """
        buf = self.get_buffer()
        if self.append:
            self.pos = buf.seek(0, io.SEEK_END)
        buf.seek(self.pos)
        buf.write(data)
        self.pos = buf.tell()
        self.bytes_written += len(data)
        if self.origin:
            self.origin.bytes_written += len(data)

    def remove_data(self):
        buf = self.get_buffer()
        buf.seek(0)
        buf.truncate()
        self.pos = 0

    def handle_file_data(self):
        """Get the data to return from a read request, based on the emulation config."""
        if not self.config:
            return io.BytesIO(b"")

        path = getattr(self.config, "path", None)
        if path:
            path = normalize_response_path(path)
            with open(path, "rb") as f:
                return io.BytesIO(f.read())
        bf = getattr(self.config, "byte_fill", None)
        if bf:
            byte = bf.byte
            if byte.startswith("0x"):
                byte = 0xFF & int(byte, 0)
            else:
                byte = 0xFF & int(byte, 16)
            size = bf.size
            b = (byte).to_bytes(1, "little")
            return io.BytesIO(b * size)
        return io.BytesIO(b"")


class NullDevice(File):
    """The NUL device: reads give no data and writes discard the data."""

    def duplicate(self):
        return NullDevice(self.path)

    def get_data(self, size=-1, reset_pointer=False):
        return b""

    def add_data(self, data):
        pass

    def write_data(self, data):
        pass


class Pipe(File):
    """Emulated named pipe objects."""

    def __init__(self, name, mode, num_instances, out_size, in_size, config=None):
        super().__init__(path=name, config=config)
        self.name: str = name
        self.mode: int = mode
        self.num_instances: int = num_instances
        self.out_size: int = out_size
        self.in_size: int = in_size


class FileManager:
    """Manages file system activity during emulation."""

    def __init__(self, config, emu):
        super().__init__()
        # A view keeps its mapping after the last handle to the mapping closes
        self.mappings: list[FileMap] = []

        # top level config
        self.config: SpeakeasyConfig = config

        # "files" key of config
        self.file_config: FilesystemConfig = self.config.filesystem
        self.emu: Any = emu

        cmdline = self.config.command_line or ""

        self.emulated_binname: str = shlex.split(cmdline)[0] if cmdline else ""

        # First file in this list seems to always be the module itself
        self.files: list[File] = []
        self.deleted_paths: set[str] = set()

        full_path_entries = [f for f in self.file_config.files if f.mode == "full_path"]
        if full_path_entries:
            logger.info("Emulated filesystem: %d full_path entries", len(full_path_entries))
            for f in full_path_entries:
                logger.debug("  emu_path=%s  host_path=%s", f.emu_path, getattr(f, "path", None))

    def new_handle(self, obj: File | FileMap) -> int:
        """Open a handle to a file, pipe or mapping in the handle table of the current process."""
        table: HandleTable = self.emu.get_handle_table()
        return table.new_handle(obj)

    def get_handle_object(self, handle, *types: type):
        """Get the object of an open handle if it is one of ``types``, else None."""
        if handle is None:
            return None
        return self.emu.get_handle_table().get(handle, *types)

    def file_create_mapping(self, hfile, name, size, prot) -> int | None:
        """
        Create a mapping of the file of ``hfile``, or of no file for NULL or INVALID_HANDLE_VALUE.

        Return None if ``hfile`` is not an open file handle.
        """
        f = None
        if hfile and ct.c_int32(hfile).value != windefs.INVALID_HANDLE_VALUE:
            f = self.get_file(hfile)
            if f is None:
                return None
        fm = FileMap(name, size, prot, f)
        self.mappings.append(fm)
        return self.new_handle(fm)

    def walk_files(self):
        for f in self.file_config.files:
            path = getattr(f, "emu_path", None)
            if not path:
                continue
            yield path

    def find_matching_entries(self, search):
        r"""
        Yield the immediate children that match a search pattern.

        A pattern is for example ``C:\*`` or ``C:\Windows\*.exe``. Each item is a
        ``(name, is_dir)`` tuple. The method synthesizes directory entries from the
        configured file paths.
        """
        search_dir = ntpath.dirname(search)
        pattern = ntpath.basename(search)
        if not pattern:
            return

        search_dir_lower = search_dir.lower().rstrip("\\")
        seen = set()

        for emu_path in self.walk_files():
            emu_lower = emu_path.lower()
            if not emu_lower.startswith(search_dir_lower + "\\"):
                continue
            remainder = emu_lower[len(search_dir_lower) + 1 :]
            parts = remainder.split("\\")
            child = parts[0]
            is_dir = len(parts) > 1
            if child in seen:
                continue
            if fnmatch.fnmatch(child, pattern.lower()):
                seen.add(child)
                yield (child, is_dir)

    def get_dropped_files(self) -> list[File]:
        return [f for f in self.files if f.bytes_written >= f.get_size()]

    def open_mapping(self, name):
        """Open a new handle to the named file mapping, or return None when no mapping has the name."""
        key = get_object_name_key(name)
        for fm in self.mappings:
            if fm.name and get_object_name_key(fm.name) == key:
                return self.new_handle(fm)
        return None

    def get_mapping_from_addr(self, addr):
        for fmap in self.mappings:
            if addr in fmap.views:
                return fmap

    def get_file_from_handle(self, handle):
        """Get the file of a handle, or None for a pipe or a handle that is not a file."""
        f = self.get_handle_object(handle, File)
        return None if isinstance(f, Pipe) else f

    def get_file(self, handle) -> File | None:
        """Get the file of an open handle, or None if the handle is not open or refers to a pipe or another object."""
        table: HandleTable = self.emu.get_handle_table()
        f = table.get(handle, File)
        return None if isinstance(f, Pipe) else f

    def get_pipe(self, handle) -> Pipe | None:
        """Get the pipe of an open handle, or None if the handle is not open or refers to another object."""
        table: HandleTable = self.emu.get_handle_table()
        return table.get(handle, Pipe)

    def get_mapping(self, handle) -> FileMap | None:
        """Get the file mapping of an open handle, or None if the handle is not open or refers to another object."""
        table: HandleTable = self.emu.get_handle_table()
        return table.get(handle, FileMap)

    def get_full_path(self, path):
        """Resolve a relative path against the current directory."""
        if ntpath.isabs(path):
            return path
        return ntpath.normpath(ntpath.join(self.config.current_dir, path))

    def get_file_from_path(self, path):
        path = self.get_full_path(path)
        for f in self.files:
            if f.path.lower() == path.lower():
                return f
        if self.is_image_alias(path):
            return self.files[0]
        return None

    def is_image_alias(self, path):
        """
        Test if a full path names the sample by the program name of the command line.

        The sample is the first file. The name refers to it only when the sample is the
        image of the current process, so not in a DLL run.
        """
        if not self.emulated_binname or not self.files:
            return False
        if path.lower() != self.get_full_path(self.emulated_binname).lower():
            return False
        proc = self.emu.get_current_process()
        return proc is not None and (proc.path or "").lower() == self.files[0].path.lower()

    def add_existing_file(self, path, data):
        """Register an existing file that the emulation space already includes, with its data."""
        f = File(path, data=data)
        self.files.append(f)
        return f

    def create_file(self, path):
        f = self.get_file_from_path(path)
        if f:
            self.files.remove(f)
        self.deleted_paths.discard(get_path_key(self.get_full_path(path)))
        f = File(path)
        self.files.append(f)
        return f

    def delete_file(self, path):
        self.deleted_paths.add(get_path_key(self.get_full_path(path)))
        f = self.get_file_from_path(path)
        if f:
            self.files.remove(f)
            return True
        return False

    def get_emu_file(self, path):
        path = self.get_full_path(path)
        if get_path_key(path) in self.deleted_paths:
            return None

        # Does this file exist in our emulation environment
        # See if we have a handler for this exact file
        for f in self.file_config.files:
            if f.mode == "full_path":
                if fnmatch.fnmatch(path.lower(), f.emu_path.lower()):
                    return f

        # Configured modules exist on disk, without content.
        modules = self.config.modules
        if any(m.path == path for m in modules.user_modules) or any(m.path == path for m in modules.system_modules):
            return FileEntryFullPath(mode="full_path", emu_path=path)

        # If no full path handler exists, do we have an extension handler?
        for f in self.file_config.files:
            path_ext = ntpath.splitext(path)[-1:][0].strip(".")
            if path_ext:
                if f.mode == "by_ext":
                    if path_ext.lower() == f.ext:
                        return f

        # Finally, do we have a catch-all default handler?
        for f in self.file_config.files:
            if f.mode == "default":
                return f
        return None

    def pipe_open(self, path, mode, num_instances, out_size, in_size):
        fconf = self.get_emu_file(path)
        if not fconf:
            fconf = {}
        p = Pipe(path, mode, num_instances, out_size, in_size, config=fconf)
        return self.new_handle(p)

    def get_directories(self):
        """
        Get the keys of the directories that exist.

        These are the current directory, the directories that the environment names, the
        parents of the known files, and their ancestors.
        """
        env = {k.lower(): v for k, v in self.config.env.items()}
        dirs = [self.config.current_dir]
        for name in DIRECTORY_ENV_VARS:
            dirs.extend(env.get(name, "").split(";"))
        modules = self.config.modules
        files = [*self.walk_files(), *(f.path for f in self.files)]
        files += [m.path for m in modules.user_modules if m.path]
        files += [m.path for m in modules.system_modules if m.path]
        dirs.extend(ntpath.dirname(f) for f in files)

        keys = set()
        for d in dirs:
            if not ntpath.splitdrive(d)[0] or "*" in d or "?" in d:
                continue
            key = get_path_key(d)
            while key not in keys:
                keys.add(key)
                key = get_path_key(ntpath.dirname(key))
        return keys

    def is_directory(self, path):
        return get_path_key(self.get_full_path(path)) in self.get_directories()

    def does_file_exist(self, path):
        if is_null_device(path):
            return True
        if self.get_file_from_path(path):
            return True

        if self.get_emu_file(path):
            return True
        return False

    def does_file_exist_by_path(self, path):
        """
        Test if a file exists that the program created or that the configuration names.

        The configuration names the file by its full path. The by_ext and default handlers
        serve content for any matching path, so they do not count.
        """
        if self.get_file_from_path(path):
            return True
        fconf = self.get_emu_file(path)
        return fconf is not None and fconf.mode == "full_path"

    def get_object_from_handle(self, handle):
        return self.get_handle_object(handle, FileMap, File)

    def file_open(self, path, create=False, truncate=False, is_dir=False):
        f: File | None
        if is_null_device(path):
            return self.new_handle(NullDevice(path))

        hnd = None
        path = self.get_full_path(path)

        if create:
            f = self.create_file(path)
            hnd = self.new_handle(f)
        else:
            f = self.get_file_from_path(path)

            if f:
                # Deep-copy this file so we can have separate file
                # offset pointers
                return self.new_handle(f.duplicate())

            fconf = self.get_emu_file(path)
            if not fconf:
                logger.debug("file_open: no handler for path %r", path)
                return hnd

            real_path = getattr(fconf, "path", None) or ""
            real_path = normalize_response_path(real_path)
            if not truncate:
                if real_path and not os.path.exists(real_path):
                    raise FileSystemEmuError(f"File path not found: {real_path}")
                f = File(path, config=fconf)
                self.files.append(f)
            else:
                if real_path and not os.path.exists(real_path):
                    raise FileSystemEmuError(f"File path not found: {real_path}")
                f = File(path, config=fconf)
                self.files.append(f)
            hnd = self.new_handle(f)

        return hnd
