# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.arch as _arch
from speakeasy.profiler import Run
from speakeasy.struct import EmuStruct
from speakeasy.errors import ApiEmuError
import speakeasy.windows.common as winemu

import speakeasy.winenv.defs.nt.ntoskrnl as ntos


class ApiHandler(object):
    """
    Base class for handling exported functions
    """

    name = ''

    @staticmethod
    def apihook(impname=None, argc=0, conv=_arch.CALL_CONV_STDCALL, ordinal=None):

        def apitemp(f):
            if not callable(f):
                raise ApiEmuError('Invalid function type supplied: %s' % (str(f)))
            f.__apihook__ = (impname or f.__name__, f, argc, conv, ordinal)
            return f

        return apitemp

    @staticmethod
    def impdata(impname):

        def datatmp(f):
            if not callable(f):
                raise ApiEmuError('Invalid function type supplied: %s' % (str(f)))
            f.__datahook__ = (impname, f)
            return f

        return datatmp

    @staticmethod
    def get_api_name(func):
        return func.__apihook__[0]

    def __init__(self, emu):
        super(ApiHandler, self).__init__()
        self.funcs = {}
        self.data = {}
        self.mod_name = ''
        self.emu = emu
        arch = self.emu.get_arch()

        if arch == _arch.ARCH_X86:
            self.ptr_size = 4
        elif arch == _arch.ARCH_AMD64:
            self.ptr_size = 8
        else:
            raise ApiEmuError('Invalid architecture')

        for name in dir(self):
            val = getattr(self, name, None)
            if val is None:
                continue

            func_attrs = getattr(val, '__apihook__', None)
            data_attrs = getattr(val, '__datahook__', None)
            if func_attrs:
                name, func, argc, conv, ordinal = func_attrs
                self.funcs[name] = (name, func, argc, conv, ordinal)
                if ordinal:
                    self.funcs[ordinal] = (name, func, argc, conv, ordinal)

            elif data_attrs:
                name, func = data_attrs
                self.data[name] = func

    def __get_hook_attrs__(self, obj):
        for name in dir(obj):
            val = getattr(obj, name, None)
            if val is None:
                continue

            func_attrs = getattr(val, '__apihook__', None)
            data_attrs = getattr(val, '__datahook__', None)
            if func_attrs:
                name, func, argc, conv, ordinal = func_attrs
                obj.funcs[name] = (name, func, argc, conv, ordinal)
                if ordinal:
                    obj.funcs[ordinal] = (name, func, argc, conv, ordinal)

            elif data_attrs:
                name, func = data_attrs
                obj.data[name] = func

    def get_data_handler(self, exp_name):
        return self.data.get(exp_name)

    def get_func_handler(self, exp_name):
        if exp_name.startswith('ordinal_'):
            ord_num = exp_name.split('_')
            if len(ord_num) == 2 and ord_num[1].isdigit():
                ord_num = int(ord_num[1])
                handler = self.funcs.get(ord_num)
                if handler:
                    return handler
        return self.funcs.get(exp_name)

    def get_ptr_size(self):
        return self.ptr_size

    def sizeof(self, obj):
        if isinstance(obj, EmuStruct):
            return obj.sizeof()
        else:
            raise ApiEmuError('Invalid object')

    def get_bytes(self, obj):
        if isinstance(obj, EmuStruct):
            return obj.get_bytes()
        else:
            raise ApiEmuError('Invalid object')

    def cast(self, obj, bytez):
        if isinstance(obj, EmuStruct):
            return obj.cast(bytez)
        else:
            raise ApiEmuError('Invalid object')
        return obj

    def write_back(self, addr, obj):
        bytez = self.get_bytes(obj)
        self.emu.mem_write(addr, bytez)

    def pool_alloc(self, pool_type, size, tag):
        return self.emu.pool_alloc(pool_type, size, tag)

    def heap_alloc(self, size, heap):
        return self.emu.heap_alloc(size, heap)

    def mem_alloc(self, size, base=None, tag=None, flags=0, perms=0, shared=False, process=None):
        return self.emu.mem_map(size, base=base, tag=tag, flags=flags, perms=perms,
                                shared=shared, process=process)

    def mem_free(self, addr):
        return self.emu.mem_free(addr)

    def mem_reserve(self, size, base=None, tag=None):
        return self.emu.mem_reserve(size, base=base, tag=tag)

    def mem_cast(self, obj, addr):
        struct_bytes = self.emu.mem_read(addr, self.sizeof(obj))
        return self.cast(obj, struct_bytes)

    def mem_copy(self, dst, src, n):
        return self.emu.mem_copy(dst, src, n)

    def read_mem_string(self, addr, width, max_chars=0):
        string = self.emu.read_mem_string(addr, width=width)
        return string

    def mem_string_len(self, addr, width):
        return self.emu.mem_string_len(addr, width)

    def read_ansi_string(self, addr):
        ans = ntos.STRING(self.emu.get_ptr_size())
        ans = self.mem_cast(ans, addr)

        string = self.emu.read_mem_string(ans.Buffer, width=1)
        return string

    def read_unicode_string(self, addr):
        us = ntos.UNICODE_STRING(self.emu.get_ptr_size())
        us = self.mem_cast(us, addr)

        string = self.emu.read_mem_string(us.Buffer, width=2)
        return string

    def read_wide_string(self, addr, max_chars=0):
        string = self.emu.read_mem_string(addr, width=2, max_chars=max_chars)
        return string

    def read_string(self, addr, max_chars=0):
        string = self.emu.read_mem_string(addr, width=1, max_chars=max_chars)
        return string

    def write_mem_string(self, string, addr, width):
        return self.emu.write_mem_string(string, addr, width)

    def write_wide_string(self, string, addr):
        return self.write_mem_string(string, addr, width=2)

    def write_string(self, string, addr):
        return self.write_mem_string(string, addr, width=1)

    def queue_run(self, run_type, ep, run_args=[]):
        run = Run()
        if not isinstance(run_type, str):
            raise ApiEmuError('Invalid run type')
        if not isinstance(ep, int):
            raise ApiEmuError('Invalid run entry point')
        if not any((isinstance(run_args, list), isinstance(run_args, tuple))):
            raise ApiEmuError('Invalid run args')

        run.type = run_type
        run.start_addr = ep
        run.args = run_args
        self.emu.add_run(run)

    def log_file_access(self, path, event_type, data=None,
                        handle=0, disposition=[], access=[], buffer=0,
                        size=None):
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            profiler.log_file_access(run, path, event_type, data, handle,
                                     disposition, access, buffer, size)

    def log_process_event(self, proc, event_type, **kwargs):
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            profiler.log_process_event(run, proc, event_type, kwargs)

    def log_registry_access(self, path, event_type, value_name=None, data=None,
                            handle=0, disposition=[], access=[], buffer=0,
                            size=None):
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            profiler.log_registry_access(run, path, event_type, value_name, data, handle,
                                         disposition, access, buffer, size)

    def log_dns(self, domain, ip=''):
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            profiler.log_dns(run, domain, ip)

    def log_network(self, server, port, typ='unknown', proto='unknown', data=b'', method=''):
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            profiler.log_network(run, server, port, typ=typ, proto=proto,
                                 data=data, method=method)

    def log_http(self, server, port, headers='', body=b'', secure=False):
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            profiler.log_http(run, server, port, headers=headers,
                              body=body, secure=secure)

    def get_max_int(self):
        # Byte order is irrelevant here
        return int.from_bytes(b'\xFF' * self.get_ptr_size(), 'little')

    def mem_read(self, addr, size):
        return self.emu.mem_read(addr, size)

    def file_open(self, path, create=False):
        return self.emu.file_open(path, create)

    def file_create_mapping(self, hfile, name, size, prot):
        return self.emu.file_create_mapping(hfile, name, size, prot)

    def file_get(self, handle):
        return self.emu.file_get(handle)

    def does_file_exist(self, path):
        return self.emu.does_file_exist(path)

    def reg_open_key(self, path, create=False):
        return self.emu.reg_open_key(path, create)

    def reg_get_key(self, handle):
        return self.emu.reg_get_key(handle)

    def reg_get_subkeys(self, hkey):
        return self.emu.reg_get_subkeys(hkey)

    def get_encoding(self, char_width):
        if char_width == 2:
            enc = 'utf-16le'
        elif char_width == 1:
            enc = 'utf-8'
        else:
            raise ApiEmuError('No encoding found for char width: %d' % (char_width))
        return enc

    def mem_write(self, addr, data):

        # If the data being written to a shared memory mapping, update all mappings
        # This will likely have to be made more robust to handle more complicated
        # scenarios with varying file offsets
        mm = self.emu.get_address_map(addr)
        if mm and mm.shared:
            fm = self.emu.get_file_manager()
            fmap = fm.get_mapping_from_addr(mm.get_base())
            if fmap:
                for base, view in fmap.views.items():
                    if base == mm.get_base():
                        continue
                    tgt_offset = addr - mm.get_base()
                    self.emu.mem_write(base + tgt_offset, data)

        return self.emu.mem_write(addr, data)

    def create_thread(self, addr, ctx, hproc, thread_type='thread', is_suspended=False):
        return self.emu.create_thread(addr, ctx, hproc, thread_type=thread_type,
                                      is_suspended=is_suspended)

    def get_object_from_id(self, id):
        return self.emu.get_object_from_id(id)

    def get_object_from_addr(self, addr):
        return self.emu.get_object_from_addr(addr)

    def get_object_handle(self, obj):
        return self.emu.get_object_handle(obj)

    def get_object_from_handle(self, hnd):
        return self.emu.get_object_from_handle(hnd)

    def get_object_from_name(self, name):
        return self.emu.get_object_from_name(name)

    def get_os_version(self):
        return self.emu.osversion

    def exit_process(self):
        self.emu.exit_process()

    def get_char_width(self, ctx):
        """
        Based on the API name, determine the character width
        being used by the function
        """
        name = ctx.get('func_name', '')
        if name.endswith('A'):
            return 1
        elif name.endswith('W'):
            return 2
        raise ApiEmuError('Failed to get character width from function: %s' % (name))

    def get_va_arg_count(self, fmt):
        """
        Get the number of arguments in the variable argument list
        """

        # Ignore escapes
        i = fmt.count('%%')
        c = fmt.count('%')

        if self.get_ptr_size() != 8:
            c += fmt.count('%ll')
        return c - i

    def va_args(self, va_list, num_args):
        """
        Get the variable argument list
        """
        args = []
        ptr = va_list
        ptrsize = self.get_ptr_size()

        for n in range(num_args):
            arg = int.from_bytes(self.emu.mem_read(ptr, ptrsize), 'little')
            args.append(arg)
            ptr += ptrsize
        return args

    def setup_callback(self, func, args, caller_argv=[]):
        """
        For APIs that call functions, we will setup the stack to make this flow
        naturally.
        """

        run = self.emu.get_current_run()

        if not len(run.api_callbacks):
            # Get the original return address
            ret = self.emu.get_ret_address()
            sp = self.emu.get_stack_ptr()

            self.emu.set_func_args(sp, winemu.API_CALLBACK_HANDLER_ADDR, *args)
            self.emu.set_pc(func)
            run.api_callbacks.append((ret, func, caller_argv))
        else:
            run.api_callbacks.append((None, func, args))

    def do_str_format(self, string, argv):
        """
        Format a string similar to msvcrt.printf
        """

        # Skip over the format string
        args = list(argv)
        new = list(string)
        curr_fmt = ''
        new_fmts = []

        # Very brittle format string parser, should improve later
        inside_fmt = False
        for i, c in enumerate(string):

            if c == '%':
                if inside_fmt:
                    inside_fmt = False
                else:
                    inside_fmt = True

            if inside_fmt:
                if c == 'S':
                    s = self.read_wide_string(args.pop(0))
                    new_fmts.append(s)
                    new[i] = 's'
                    inside_fmt = False

                elif c == 's':
                    if curr_fmt.startswith('w'):
                        s = self.read_wide_string(args.pop(0))
                        new[i - 1] = '\xFF'
                        curr_fmt = ''
                        new_fmts.append(s)
                    else:
                        s = self.read_string(args.pop(0))
                        new_fmts.append(s)
                elif c in ('x', 'X', 'd', 'u', 'i'):
                    if curr_fmt.startswith('ll'):
                        if self.get_ptr_size() == 8:
                            new_fmts.append(args.pop(0))
                        else:
                            low = args.pop(0)
                            high = args.pop(0)
                            new_fmts.append(high << 32 | low)
                        new = new[: i - 2] + new[i:]
                        curr_fmt = ''
                    else:
                        new_fmts.append(0xFFFFFFFF & args.pop(0))
                elif c == 'c':
                    new_fmts.append(0xFF & args.pop(0))
                elif c == 'P':
                    new[i] = 'X'
                    new_fmts.append(args.pop(0))
                elif c == 'p':
                    new[i] = 'x'
                    new_fmts.append(args.pop(0))
                elif c == 'l':
                    curr_fmt += c
                elif c == 'w':
                    curr_fmt += c

            if inside_fmt and c in 'diuoxXfFeEgGaAcspn':
                inside_fmt = False

            if not args:
                break

        new = ''.join(new)
        new = new.replace('\xFF', '')
        new = new % tuple(new_fmts)

        return new
