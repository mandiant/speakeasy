import base64
import zlib

from speakeasy.report import MemoryAccesses, MemoryRegion


def test_memory_region_without_data():
    """Existing regions without data still parse correctly."""
    region = MemoryRegion(
        tag="emu.module.test.0x400000",
        address=0x400000,
        size=0x1000,
        prot="rwx",
    )
    assert region.data is None


def test_memory_region_with_data():
    """Region with compressed base64 data field."""
    raw_bytes = b"\x4d\x5a\x90\x00" * 16
    compressed = zlib.compress(raw_bytes)
    encoded = base64.b64encode(compressed).decode()

    region = MemoryRegion(
        tag="emu.module.test.0x400000",
        address=0x400000,
        size=len(raw_bytes),
        prot="rwx",
        accesses=MemoryAccesses(reads=10, writes=5, execs=100),
        data=encoded,
    )
    assert region.data == encoded

    recovered = zlib.decompress(base64.b64decode(region.data))
    assert recovered == raw_bytes


def test_memory_region_data_roundtrip_json():
    """data field survives JSON serialization."""
    raw_bytes = b"\xde\xad\xbe\xef" * 4
    compressed = zlib.compress(raw_bytes)
    encoded = base64.b64encode(compressed).decode()

    region = MemoryRegion(
        tag="test",
        address=0x1000,
        size=16,
        prot="rw-",
        data=encoded,
    )
    json_str = region.model_dump_json()
    restored = MemoryRegion.model_validate_json(json_str)
    assert restored.data == encoded

    recovered = zlib.decompress(base64.b64decode(restored.data))
    assert recovered == raw_bytes
