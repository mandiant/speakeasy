"""The max_instructions limit applies to each queued run; the exit event stops all runs."""

import threading

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


def test_exit_event_stops_an_api_loop_as_a_timeout(config):
    config.update({"timeout": 60, "max_api_count": 10_000_000})
    exit_event = threading.Event()
    se = Speakeasy(config=config, exit_event=exit_event)
    try:
        # CreateThread(NULL, 0, thread, NULL, 0, NULL); loop: mov eax, GetTickCount; call eax; jmp loop
        code = b"\x6a\0\x6a\0\x6a\0\x68" + b"\0" * 4 + b"\x6a\0\x6a\0\xb8" + b"\0" * 4 + b"\xff\xd0"
        loop = len(code)
        code += b"\xb8" + b"\0" * 4 + b"\xff\xd0\xeb\xf7"
        thread = len(code)
        code += b"\xb8\x2a\0\0\0\xc3"
        base = se.load_shellcode(data=code, arch="x86")
        se.mem_write(base + 7, (base + thread).to_bytes(4, "little"))
        se.mem_write(base + 16, se.emu.get_proc("kernel32", "CreateThread").to_bytes(4, "little"))
        se.mem_write(base + loop + 1, se.emu.get_proc("kernel32", "GetTickCount").to_bytes(4, "little"))
        calls = []

        def count_ticks(emu, api_name, func, params):
            calls.append(api_name)
            if len(calls) == 100:
                exit_event.set()
            return len(calls)

        se.add_api_hook(count_ticks, "kernel32", "GetTickCount", argc=0)

        se.run_shellcode(base)

        assert exit_event.is_set()
        (entry,) = se.get_report().entry_points
        assert entry.error is not None
        assert entry.error.type == "timeout"
        assert base + loop <= int(entry.error.pc) < base + thread
    finally:
        se.shutdown()
