import pytest

from speakeasy.winenv.api.usermode.kernel32 import Kernel32


class Memory:
    get_char_width = Kernel32.get_char_width

    def __init__(self, device="C:"):
        self.device = device
        self.writes = {}
        self.error = None
        self.read_width = None

    def mem_write(self, address, data):
        self.writes[address] = data

    def read_mem_string(self, address, width):
        self.read_width = width
        return self.device

    def set_last_error(self, value):
        self.error = value


@pytest.mark.parametrize("wide", [False, True])
def test_query_dos_device_mapping_and_exact_capacity(wide):
    memory = Memory("c:")
    ctx = {"func_name": "kernel32.QueryDosDeviceW" if wide else "kernel32.QueryDosDeviceA"}
    expected = "\\Device\\HarddiskVolume1\0\0".encode("utf-16le" if wide else "ascii")
    width = 2 if wide else 1
    count = len(expected) // width
    assert Kernel32.QueryDosDevice(memory, memory, [8, 16, count], ctx) == count
    assert memory.writes == {16: expected}
    assert memory.read_width == width
    memory.writes.clear()
    assert Kernel32.QueryDosDevice(memory, memory, [8, 16, count - 1], ctx) == 0
    assert memory.error == 122
    assert not memory.writes


@pytest.mark.parametrize("wide", [False, True])
def test_query_dos_device_enumerates_names(wide):
    memory = Memory()
    ctx = {"func_name": "kernel32.QueryDosDeviceW" if wide else "kernel32.QueryDosDeviceA"}
    assert Kernel32.QueryDosDevice(memory, memory, [0, 16, 4], ctx) == 4
    assert memory.writes == {16: "C:\0\0".encode("utf-16le" if wide else "ascii")}
    assert memory.read_width is None


@pytest.mark.parametrize("device", ["", "Z:", "C:\\"])
@pytest.mark.parametrize("wide", [False, True])
def test_query_dos_device_unknown_name_leaves_buffer_untouched(device, wide):
    memory = Memory(device)
    ctx = {"func_name": "kernel32.QueryDosDeviceW" if wide else "kernel32.QueryDosDeviceA"}
    assert Kernel32.QueryDosDevice(memory, memory, [8, 16, 100], ctx) == 0
    assert memory.error == 2
    assert not memory.writes


def test_query_dos_device_rejects_null_output():
    memory = Memory()
    assert Kernel32.QueryDosDevice(memory, memory, [0, 0, 100], {"func_name": "QueryDosDeviceA"}) == 0
    assert memory.error == 87
    assert not memory.writes
