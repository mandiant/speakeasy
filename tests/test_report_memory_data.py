from speakeasy.report import DroppedFile, MemoryAccesses, MemoryRegion


def test_memory_region_roundtrip_with_data_ref():
    region = MemoryRegion(
        tag="emu.module.test.0x400000",
        address=0x400000,
        size=0x1000,
        prot="rwx",
        accesses=MemoryAccesses(reads=10, writes=5, execs=100),
        data_ref="sha256-region",
    )

    restored = MemoryRegion.model_validate_json(region.model_dump_json())

    assert restored.data_ref == "sha256-region"


def test_dropped_file_roundtrip_with_data_ref():
    dropped = DroppedFile(path="C:\\temp\\drop.bin", size=7, sha256="sha256-file", data_ref="sha256-file")

    restored = DroppedFile.model_validate_json(dropped.model_dump_json())

    assert restored.data_ref == "sha256-file"
    assert restored.size == 7
