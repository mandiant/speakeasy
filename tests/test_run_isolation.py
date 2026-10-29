import pytest

import speakeasy.winenv.arch as e_arch
from speakeasy import Speakeasy


@pytest.mark.parametrize(
    "bin_file,arch",
    [
        ("dll_test_x86.dll.xz", e_arch.ARCH_X86),
        ("dll_test_x64.dll.xz", e_arch.ARCH_AMD64),
    ],
)
def test_registers_reset_between_runs(config, load_test_bin, bin_file, arch):
    """Each run must start with zeroed GP registers and DF=0."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config, argv=[])
    module = se.load_module(data=data)

    run_register_snapshots = []
    seen_runs = set()

    if arch == e_arch.ARCH_X86:
        gp_regs = [
            e_arch.X86_REG_EAX,
            e_arch.X86_REG_EBX,
            e_arch.X86_REG_ECX,
            e_arch.X86_REG_EDX,
            e_arch.X86_REG_ESI,
            e_arch.X86_REG_EDI,
        ]
    else:
        gp_regs = [
            e_arch.AMD64_REG_RAX,
            e_arch.AMD64_REG_RBX,
            e_arch.AMD64_REG_RCX,
            e_arch.AMD64_REG_RDX,
            e_arch.AMD64_REG_RSI,
            e_arch.AMD64_REG_RDI,
            e_arch.AMD64_REG_R8,
            e_arch.AMD64_REG_R9,
            e_arch.AMD64_REG_R10,
            e_arch.AMD64_REG_R11,
            e_arch.AMD64_REG_R12,
            e_arch.AMD64_REG_R13,
            e_arch.AMD64_REG_R14,
            e_arch.AMD64_REG_R15,
        ]

    def code_hook(emu, addr, size):
        run_id = id(se.emu.curr_run)
        if run_id not in seen_runs:
            seen_runs.add(run_id)
            snapshot = {}
            for reg in gp_regs:
                snapshot[reg] = se.emu.reg_read(reg)
            eflags = se.emu.reg_read(e_arch.X86_REG_EFLAGS)
            snapshot["df"] = bool(eflags & (1 << 10))
            run_register_snapshots.append(snapshot)

    se.emu.add_code_hook(cb=code_hook)
    se.run_module(module, all_entrypoints=True)
    se.shutdown()

    assert len(run_register_snapshots) > 1, "Need multiple runs to test isolation"

    for i, snapshot in enumerate(run_register_snapshots[1:], 1):
        if arch == e_arch.ARCH_X86:
            for reg in gp_regs:
                assert snapshot[reg] == 0, f"Run {i}: register should be 0, got {snapshot[reg]:#x}"
        else:
            non_arg_regs = [
                e_arch.AMD64_REG_RAX,
                e_arch.AMD64_REG_RBX,
                e_arch.AMD64_REG_RSI,
                e_arch.AMD64_REG_RDI,
                e_arch.AMD64_REG_R10,
                e_arch.AMD64_REG_R11,
                e_arch.AMD64_REG_R12,
                e_arch.AMD64_REG_R13,
                e_arch.AMD64_REG_R14,
                e_arch.AMD64_REG_R15,
            ]
            for reg in non_arg_regs:
                assert snapshot[reg] == 0, f"Run {i}: register should be 0, got {snapshot[reg]:#x}"
        assert not snapshot["df"], f"Run {i}: DF should be clear"


@pytest.mark.parametrize("bin_file", ["dll_test_x86.dll.xz"])
def test_stack_cleared_between_runs(config, load_test_bin, bin_file):
    """Stack memory must be zeroed at the start of each run."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config, argv=[])
    module = se.load_module(data=data)

    stack_snapshots = []
    seen_runs = set()
    SAMPLE_SIZE = 256

    def code_hook(emu, addr, size):
        run_id = id(se.emu.curr_run)
        if run_id not in seen_runs:
            seen_runs.add(run_id)
            sp = se.emu.get_stack_ptr()
            try:
                data_below = se.emu.mem_read(sp - SAMPLE_SIZE, SAMPLE_SIZE)
                stack_snapshots.append(bytes(data_below))
            except Exception:
                stack_snapshots.append(None)

    se.emu.add_code_hook(cb=code_hook)
    se.run_module(module, all_entrypoints=True)
    se.shutdown()

    assert len(stack_snapshots) > 1

    for i, snap in enumerate(stack_snapshots[1:], 1):
        if snap is not None:
            assert snap == b"\x00" * SAMPLE_SIZE, f"Run {i}: stack below SP should be zeroed"
