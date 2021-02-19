# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from ctypes import *  # noqa
from collections import OrderedDict


class EmuStructException(Exception):
    """
    Container class for struct exceptions
    """
    pass


class Enum(object):
    """
    For now, a basic python object will serve as a C style enum
    """
    pass


class PtrMeta(type):
    """
    Metaclass for pointer types
    """
    def __mul__(self, mult):
        return tuple((self, mult))


class Ptr(object, metaclass=PtrMeta):
    """
    Generic object to identify pointer variables that will be expanded
    according to the "ptr_size" parameter passed to our init
    """
    _points_to_ = None


class CMeta(type):
    """
    meta class to hook __call__ and make __dict__ ordered on all versions
    of python
    """

    @classmethod
    def __prepare__(self, name, bases):
        # This is default behavior for Python 3.6+ but lets do this anyway
        # to make sure __dict__ is ordered on older versions
        return OrderedDict()

    def __new__(self, name, bases, classdict):
        classdict['__ordered__'] = [k for k in classdict.keys()
                                    if k not in ('__module__', '__qualname__')]
        return type.__new__(self, name, bases, classdict)

    def __call__(cls, *args, **kwargs):

        obj = type.__call__(cls, *args, **kwargs)
        obj.create_struct()
        return obj

    def __mul__(self, mult):
        return tuple((self, mult))


class EmuStruct(object, metaclass=CMeta):
    """
    Advanced Python class for interacting with C structures
    """

    # Save the unique types we create here
    # This is necessary since the ctypes metaclass won't allow us
    # to assign structures even if the types are identical on the surface.
    # ctypes will test the id (address) of the type to make sure they match
    # upon assignment. Otherwise we will hit spurious TypeErrors.
    __types__ = {}

    class FilteredStruct(ct.Structure):
        def __hash__(self):
            return hash(repr(self))

    def __init__(self, ptr_size=0, pack=0):

        # Set __dict__ directly here to avoid __getattribute__ loops
        self.__dict__['__pack__'] = pack
        self.__dict__['__struct__'] = None
        self.__dict__['__fields__'] = []
        self.__dict__['__ptrsize__'] = ptr_size
        self.__dict__['__filtermap__'] = {}

    def _is_ctype(self, obj):
        """
        Test whether the object has a ctype base
        """
        tests = (ct._SimpleCData, ct.Structure, ct.Union, ct.Array)
        return any([issubclass(obj, t) for t in tests])

    def create_struct(self, types={}):
        """
        Walk each attribute and handle accordingly. Since ctypes.Structure
        is a metaclass, we have to build the "_fields_" dynamically via a
        factory
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
                                raise EmuStructException(str(e))

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
                                raise EmuStructException(str(e))
                        cts = filt.__struct__
                        self.__filtermap__.update({d: filt})
                        self.__fields__.append((d, cts.__class__))

            except TypeError:
                continue
        self.__init_struct()

    def get_ptr_field(self):
        """
        Get ctypes value for the required pointer size
        """
        if self.__ptrsize__ == 4:
            return ct.c_uint32
        elif self.__ptrsize__ == 8:
            return ct.c_uint64
        else:
            return ct.c_void_p

    def get_pack(self):
        """
        Get the required structure pack (defaults to pointer size)
        """
        if self.__pack__:
            return self.__pack__
        else:
            if self.__ptrsize__:
                return self.__ptrsize__ * 2
            else:
                return 1

    def _link_cstructs(self, obj):
        """
        Link the ctypes structures together in the case of nesting.
        This will allow the buffer API to convert it to bytes easily
        """
        for fname, subobj in obj.__filtermap__.items():

            if isinstance(subobj, list):
                x = getattr(obj.__struct__, fname)

                for i, e in enumerate(x):
                    self._link_cstructs(subobj[i])
                    x[i] = subobj[i].__struct__

            elif isinstance(subobj, EmuStruct):
                self._link_cstructs(subobj)
                setattr(obj.__struct__, fname, subobj.__struct__)

    def get_bytes(self):

        """
        Convert the structure to bytes and respecting endianness
        """

        self._link_cstructs(self)

        struct = self.__struct__
        buf = (ct.c_ubyte * ct.sizeof(struct))()
        ct.memmove(buf, ct.byref(struct), ct.sizeof(struct))
        return bytes(buf[:])

    def sizeof(self):
        """
        Get the size of the C structure
        """
        return ct.sizeof(self.__struct__)

    def _deep_cast(self, obj, bytez, offset):

        obj.__struct__ = type(obj.__struct__).from_buffer(bytearray(bytez[offset[0]:]))
        for fn, c in obj.__fields__:
            subobj = obj.__filtermap__.get(fn)
            if subobj:
                if isinstance(subobj, list):
                    for sso in subobj:
                        self._deep_cast(sso, bytez, offset)
                else:
                    self._deep_cast(subobj, bytez, offset)
            else:
                offset[0] += ct.sizeof(c)

    def cast(self, bytez):
        """
        Convert a bytes object to the C structure by "casting" them
        """
        offset = [0]
        self._deep_cast(self, bytez, offset=offset)
        return self

    def get_cstruct(self):
        return self.__struct__.__class__

    def get_sub_field_name(self, cstruc, offset):
        for (name,t) in cstruc._fields_:
            noff = cstruc.__dict__[name].offset
            nsize = cstruc.__dict__[name].size
            if offset == noff:
                return name
            elif noff < offset < noff + nsize:
                # access into the sub-structure recursively
                return name + '.' + self.get_sub_field_name(t, offset - noff)

    def get_field_name(self, offset):
        cstruc = self.get_cstruct()
        for (name,t) in self.__fields__:
            noff = cstruc.__dict__[name].offset
            nsize = cstruc.__dict__[name].size
            if offset == noff:
                return name
            elif noff < offset < noff + nsize:
                # access into the sub-structure
                return name + '.' + self.get_sub_field_name(t, offset - noff)
        return None

    def __struct_factory(self, name):
        """
        Factory used to generate ctypes structures using the ctypes metaclass
        """
        _type_name = 'ct' + name + '%d' % (self.__ptrsize__)
        _type = EmuStruct.__types__.get(_type_name)
        if not _type:
            _type = type(_type_name, (self.__class__.FilteredStruct, ),
                         {"_pack_": self.get_pack(), "_fields_": self.__fields__})
            EmuStruct.__types__[_type_name] = _type
        return _type

    def __init_struct(self):
        self.__struct__ = self.__struct_factory(self.__class__.__name__)()
        return self.__struct__

    def __setattr__(self, name, value):
        """
        Hook setattr so that accessing the underlying ctypes structure can be
        handled correctly
        """
        struct = self.__struct__
        if struct:
            fields = struct._fields_
            for fn, val in fields:
                if fn == name:
                    if type(value) == bytes:
                        barray = getattr(struct, fn)
                        barray[:len(value)] = value
                        return
                    struct.__setattr__(fn, value)
                    return
        super(EmuStruct, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        Hook getattribute so that accessing the underlying ctypes structure
        can be handled correctly
        """
        try:
            struct = super(EmuStruct, self).__getattribute__('__struct__')
            if struct:
                fields = struct._fields_
                for fn, val in fields:
                    if fn == name:
                        val = struct.__getattribute__(name)
                        tests = (EmuStruct.FilteredStruct, EmuUnion.FilteredStruct, ct.Array)
                        if any([isinstance(val, t) for t in tests]):
                            fm = super(EmuStruct,
                                       self).__getattribute__('__filtermap__')
                            filt_obj = fm.get(name)
                            if filt_obj:
                                return filt_obj

                        return struct.__getattribute__(name)
        except AttributeError:
            pass
        return super(EmuStruct, self).__getattribute__(name)


class EmuUnion(EmuStruct, metaclass=CMeta):

    class FilteredStruct(ct.Union):
        def __hash__(self):
            return hash(repr(self))
