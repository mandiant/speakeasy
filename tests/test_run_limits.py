"""The max_instructions limit applies to each queued run."""

from speakeasy import Speakeasy


def test_instruction_limit_stops_spinning_run_and_next_run_executes(config):
    config.update({"timeout": 3, "max_instructions": 1000})
    se = Speakeasy(config=config)
    try:
        # CreateThread(NULL, 0, thread, NULL, 0, NULL); JMP $; thread: MOV EAX,0x2a; RET
        code = b"\x6a\0\x6a\0\x6a\0\x68" + b"\0" * 4 + b"\x6a\0\x6a\0\xb8" + b"\0" * 4 + b"\xff\xd0\xeb\xfe"
        thread = len(code)
        code += b"\xb8\x2a\0\0\0\xc3"
        base = se.load_shellcode(data=code, arch="x86")
        se.mem_write(base + 7, (base + thread).to_bytes(4, "little"))
        se.mem_write(base + 16, se.emu.get_proc("kernel32", "CreateThread").to_bytes(4, "little"))

        se.run_shellcode(base)

        spinning, created = se.get_report().entry_points
        assert spinning.error is not None
        assert spinning.error.type == "max_instructions"
        assert int(spinning.error.pc) == base + thread - 2
        assert created.error is None
        assert created.ret_val == 0x2A
    finally:
        se.shutdown()
