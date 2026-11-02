# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from collections import OrderedDict
from collections.abc import MutableMapping
from ctypes import *  # noqa
from typing import Annotated, Any, get_args, get_origin, get_type_hints


class EmuStructException(Exception):
    """Container class for struct exceptions."""


class Enum:
    """
    Basic Python object that serves as a C style enum.

    It supports arbitrary attribute access for dynamic enum-style constants.
    """

    def __setattr__(self, name: str, value: Any) -> None:
        object.__setattr__(self, name, value)

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(name)


class PtrMeta(type):
    """Metaclass for pointer types."""

    def __mul__(self, mult):
        return tuple((self, mult))


class Ptr(metaclass=PtrMeta):
    """Generic object that identifies pointer variables, which expand to the ``ptr_size`` passed to ``__init__``."""

    _points_to_ = None


class CMeta(type):
    """Metaclass that hooks ``__call__`` and keeps ``__dict__`` ordered on all Python versions."""

    @classmethod
    def __prepare__(metacls, name: str, bases: tuple[type, ...], /, **kwds: Any) -> MutableMapping[str, object]:
        return OrderedDict()

    def __new__(self, name, bases, classdict):
        classdict["__ordered__"] = [k for k in classdict.keys() if k not in ("__module__", "__qualname__")]
        return type.__new__(self, name, bases, classdict)

    def __call__(cls, *args, **kwargs):
        obj = type.__call__(cls, *args, **kwargs)
        obj.create_struct()
        return obj

    def __mul__(self, mult):
        return tuple((self, mult))


class EmuStruct(metaclass=CMeta):
    """
    A C struct built from ctypes fields.

    A subclass declares its fields at class level, in the order of the C struct:

        class UNICODE_STRING(EmuStruct):
            Length: Annotated[int, ct.c_uint16]
            MaximumLength: Annotated[int, ct.c_uint16]
            Buffer: Annotated[int, Ptr]

    A field that depends on ``ptr_size`` or on a constructor parameter is assigned in ``__init__`` after the
    super call, for example ``self.Name = ct.c_uint8 * (4 * width)``. These fields come after the declared ones.
    """

    # Save the unique types we create here
    # This is necessary since the ctypes metaclass won't allow us
    # to assign structures even if the types are identical on the surface.
    # ctypes will test the id (address) of the type to make sure they match
    # upon assignment. Otherwise we will hit spurious TypeErrors.
    __types__: dict[tuple, type] = {}

    # The fields that each class declares at class level, resolved at its first instance
    __declared__: dict[type, list[tuple[str, Any]]] = {}

    class FilteredStruct(ct.Structure):
        def __hash__(self):
            return hash(repr(self))

    def __init__(self, ptr_size=0, pack=0):
        # Set __dict__ directly here to avoid __getattribute__ loops
        self.__dict__["__pack__"] = pack
        self.__dict__["__struct__"] = None
        self.__dict__["__fields__"] = []
        self.__dict__["__ptrsize__"] = ptr_size
        self.__dict__["__filtermap__"] = {}
        self.__dict__.update(self.get_declared_fields())

    @classmethod
    def get_declared_fields(cls) -> list[tuple[str, Any]]:
        """
        Get the fields of the class-level declarations, with the fields of the base classes first.

        A field is ``Annotated`` with its type (``x: Annotated[int, ct.c_uint32]``), or is a nested struct
        (``x: UNICODE_STRING``). The annotations are resolved at the first instance, so a field can name a
        struct that the module defines later.
        """
        fields = EmuStruct.__declared__.get(cls)
        if fields is None:
            fields = []
            for name, hint in get_type_hints(cls, include_extras=True).items():
                if get_origin(hint) is Annotated:
                    fields.append((name, get_args(hint)[1]))
                elif isinstance(hint, type) and issubclass(hint, EmuStruct):
                    fields.append((name, hint))
            EmuStruct.__declared__[cls] = fields
        return fields

    def _is_ctype(self, obj):
        """Test whether the object has a ctype base."""
        tests = (ct._SimpleCData, ct.Structure, ct.Union, ct.Array)
        return any([issubclass(obj, t) for t in tests])

    def create_struct(self):
        """
        Walk each attribute and build the ctypes structure.

        ``ctypes.Structure`` uses a metaclass, so this method builds ``_fields_`` dynamically through a factory.

        Raises:
            EmuStructException: if a nested structure cannot be built.
        """
        if self.__struct__:
            return

        for d, obj in self.__dict__.items():
            try:
                if isinstance(obj, tuple):
                    if issubclass(obj[0], EmuStruct):
                        _type, count = obj

                        try:
                            tmp = _type(self.__ptrsize__, self.__pack__)
                            array = [_type(self.__ptrsize__, self.__pack__) for i in range(count)]
                        except TypeError:
                            try:
                                tmp = _type(self.__ptrsize__)
                                array = [_type(self.__ptrsize__) for i in range(count)]
                            except TypeError as e:
                                raise EmuStructException(str(e)) from e

                        ctarray = tmp.__struct__.__class__ * count

                        self.__filtermap__.update({d: array})
                        self.__fields__.append((d, ctarray))
                    elif issubclass(obj[0], Ptr):
                        _type, count = obj
                        ptype = self.get_ptr_field()
                        self.__fields__.append((d, (ptype * count)))

            except TypeError:
                continue
            try:
                if self._is_ctype(obj):
                    # Simply append ctypes since they will be handled
                    # automatically
                    self.__fields__.append((d, obj))
                elif issubclass(obj, Ptr):
                    # Expand pointers to the required width
                    self.__fields__.append((d, self.get_ptr_field()))

                elif issubclass(obj, EmuStruct):
                    # Allow nesting of this class which we are calling a
                    # "filter class". That is, when fields are accessed in the
                    # underlying ctypes struct, we pass the getattr/setattr through
                    if obj.__name__ != self.__class__.__name__:
                        try:
                            filt = obj(self.__ptrsize__, self.__pack__)
                        except TypeError:
                            try:
                                filt = obj(self.__ptrsize__)
                            except TypeError as e:
                                raise EmuStructException(str(e)) from e
                        cts = filt.__struct__
                        self.__filtermap__.update({d: filt})
                        self.__fields__.append((d, cts.__class__))

            except TypeError:
                continue
        self.__init_struct()

    def get_ptr_field(self):
        """Get ctypes value for the required pointer size."""
        if self.__ptrsize__ == 4:
            return ct.c_uint32
        if self.__ptrsize__ == 8:
            return ct.c_uint64
        return ct.c_void_p

    def get_pack(self):
        """Get the required structure pack (defaults to pointer size)."""
        if self.__pack__:
            return self.__pack__
        if self.__ptrsize__:
            return self.__ptrsize__ * 2
        return 1

    def _link_cstructs(self, obj):
        """Link nested ctypes structures together so that the buffer API can convert them to bytes."""
        for fname, subobj in obj.__filtermap__.items():
            if isinstance(subobj, list):
                x = getattr(obj.__struct__, fname)

                for i in range(len(x)):
                    self._link_cstructs(subobj[i])
                    x[i] = subobj[i].__struct__

            elif isinstance(subobj, EmuStruct):
                self._link_cstructs(subobj)
                setattr(obj.__struct__, fname, subobj.__struct__)

    def get_bytes(self):
        """Convert the structure to bytes and respecting endianness."""
        self._link_cstructs(self)

        struct = self.__struct__
        buf = (ct.c_ubyte * ct.sizeof(struct))()
        ct.memmove(buf, ct.byref(struct), ct.sizeof(struct))
        return bytes(buf[:])

    def sizeof(self):
        """Get the size of the C structure."""
        return ct.sizeof(self.__struct__)

    def _deep_cast(self, obj, bytez, offset):
        cstruct = type(obj.__struct__)
        obj.__struct__ = cstruct.from_buffer(bytearray(bytez[offset:]))
        for fn, _ in obj.__fields__:
            subobj = obj.__filtermap__.get(fn)
            if not subobj:
                continue
            field_offset = offset + getattr(cstruct, fn).offset
            if isinstance(subobj, list):
                for i, sso in enumerate(subobj):
                    self._deep_cast(sso, bytez, field_offset + i * sso.sizeof())
            else:
                self._deep_cast(subobj, bytez, field_offset)

    def cast(self, bytez):
        """Convert a bytes object to the C structure by "casting" them."""
        self._deep_cast(self, bytez, 0)
        return self

    def get_cstruct(self):
        return self.__struct__.__class__

    def __struct_factory(self, name):
        """Factory used to generate ctypes structures using the ctypes metaclass."""
        _type_name = f"ct{name}{self.__ptrsize__}"
        key = (_type_name, self.get_pack(), tuple(self.__fields__))
        _type = EmuStruct.__types__.get(key)
        if not _type:
            _type = type(
                _type_name,
                (self.__class__.FilteredStruct,),
                {"_pack_": self.get_pack(), "_layout_": "ms", "_fields_": self.__fields__},
            )
            EmuStruct.__types__[key] = _type
        return _type

    def __init_struct(self):
        self.__struct__ = self.__struct_factory(self.__class__.__name__)()
        return self.__struct__

    def __setattr__(self, name, value):
        """Hook ``setattr`` to handle access to the underlying ctypes structure."""
        struct = self.__struct__
        if struct:
            fields = struct._fields_
            for fn, _ in fields:
                if fn == name:
                    if isinstance(value, bytes):
                        barray = getattr(struct, fn)
                        barray[: len(value)] = value
                        return
                    struct.__setattr__(fn, value)
                    return
        super().__setattr__(name, value)

    def __getattribute__(self, name):
        """Hook ``getattribute`` to handle access to the underlying ctypes structure."""
        try:
            struct = super().__getattribute__("__struct__")
            if struct:
                fields = struct._fields_
                for fn, _ in fields:
                    if fn == name:
                        val = struct.__getattribute__(name)
                        tests = (EmuStruct.FilteredStruct, EmuUnion.FilteredStruct, ct.Array)
                        if any([isinstance(val, t) for t in tests]):
                            fm = super().__getattribute__("__filtermap__")
                            filt_obj = fm.get(name)
                            if filt_obj:
                                return filt_obj

                        return struct.__getattribute__(name)
        except AttributeError:
            pass
        return super().__getattribute__(name)


class EmuUnion(EmuStruct, metaclass=CMeta):
    class FilteredStruct(ct.Union):
        def __hash__(self):
            return hash(repr(self))
