import pytest

from speakeasy.config import SpeakeasyConfig
from speakeasy.windows.win32 import Win32Emulator
from speakeasy.winenv import arch as e_arch


STACK_SIZE = 0x12000
RET_ADDR = 0xDEADBEEF


@pytest.fixture(params=[e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def emu(config, request):
    a = request.param
    cfg = SpeakeasyConfig(**config)
    e = Win32Emulator(cfg)
    e.arch = a
    e.set_ptr_size(a)
    bits = e_arch.BITS_32 if a == e_arch.ARCH_X86 else e_arch.BITS_64
    e.emu_eng.init_engine(e_arch.ARCH_X86, bits)
    base, _ = e.alloc_stack(STACK_SIZE)
    e.stack_base = base
    return e


X86_CONVS = [e_arch.CALL_CONV_CDECL, e_arch.CALL_CONV_STDCALL, e_arch.CALL_CONV_FASTCALL]
X64_CONVS = [e_arch.CALL_CONV_CDECL, e_arch.CALL_CONV_STDCALL]
ARG_COUNTS = [0, 1, 2, 3, 4, 5, 8]


def _convs_for_arch(arch):
    if arch == e_arch.ARCH_X86:
        return X86_CONVS
    return X64_CONVS


def _conv_name(conv):
    return {
        e_arch.CALL_CONV_CDECL: "cdecl",
        e_arch.CALL_CONV_STDCALL: "stdcall",
        e_arch.CALL_CONV_FASTCALL: "fastcall",
    }[conv]


def _make_args(argc):
    return [0x1000 + i for i in range(argc)]


@pytest.fixture(autouse=True)
def _reset_stack(emu):
    yield
    emu.reset_stack(emu.stack_base)


class TestSetGetFuncArgs:
    @pytest.mark.parametrize("argc", ARG_COUNTS)
    def test_round_trip(self, emu, argc):
        for conv in _convs_for_arch(emu.arch):
            args = _make_args(argc)
            emu.set_func_args(emu.stack_base, RET_ADDR, *args, conv=conv)
            got = emu.get_func_argv(conv, argc)
            assert got == args, (
                f"arch={emu.arch}, conv={_conv_name(conv)}, argc={argc}: "
                f"expected {[hex(a) for a in args]}, got {[hex(a) for a in got]}"
            )
            emu.reset_stack(emu.stack_base)

    @pytest.mark.parametrize("argc", ARG_COUNTS)
    def test_ret_address(self, emu, argc):
        for conv in _convs_for_arch(emu.arch):
            args = _make_args(argc)
            emu.set_func_args(emu.stack_base, RET_ADDR, *args, conv=conv)
            got_ret = emu.get_ret_address()
            assert got_ret == RET_ADDR, (
                f"arch={emu.arch}, conv={_conv_name(conv)}: "
                f"ret expected {hex(RET_ADDR)}, got {hex(got_ret)}"
            )
            emu.reset_stack(emu.stack_base)


class TestDoCallReturn:
    @pytest.mark.parametrize("argc", ARG_COUNTS)
    def test_x86_stdcall_stack_restored(self, emu, argc):
        if emu.arch != e_arch.ARCH_X86:
            pytest.skip("x86 only")
        conv = e_arch.CALL_CONV_STDCALL
        args = _make_args(argc)
        sp_before = emu.get_stack_ptr()
        emu.set_func_args(emu.stack_base, RET_ADDR, *args, conv=conv)
        emu.do_call_return(argc, ret_addr=RET_ADDR, conv=conv)
        sp_after = emu.get_stack_ptr()
        assert sp_after == sp_before

    @pytest.mark.parametrize("argc", ARG_COUNTS)
    def test_x86_fastcall_stack_restored(self, emu, argc):
        if emu.arch != e_arch.ARCH_X86:
            pytest.skip("x86 only")
        conv = e_arch.CALL_CONV_FASTCALL
        args = _make_args(argc)
        sp_before = emu.get_stack_ptr()
        emu.set_func_args(emu.stack_base, RET_ADDR, *args, conv=conv)
        emu.do_call_return(argc, ret_addr=RET_ADDR, conv=conv)
        sp_after = emu.get_stack_ptr()
        assert sp_after == sp_before
