import base64
import zlib

from speakeasy.artifacts import ArtifactStore
from speakeasy.report import DataArtifact, MemoryAccesses, MemoryRegion, Report


def decode_artifact(entry: DataArtifact) -> bytes:
    return zlib.decompress(base64.b64decode(entry.data))


def test_artifact_store_deduplicates_payloads():
    store = ArtifactStore()

    first_ref = store.put_bytes(b"artifact-bytes")
    second_ref = store.put_bytes(b"artifact-bytes")

    assert first_ref == second_ref
    report_data = store.to_report_data()
    assert list(report_data) == [first_ref]
    assert decode_artifact(report_data[first_ref]) == b"artifact-bytes"


def test_memory_region_data_ref_roundtrip_json():
    region = MemoryRegion(
        tag="test",
        address=0x1000,
        size=16,
        prot="rw-",
        accesses=MemoryAccesses(reads=1, writes=2, execs=3),
        data_ref="abc123",
    )

    json_str = region.model_dump_json()
    restored = MemoryRegion.model_validate_json(json_str)

    assert restored.data_ref == "abc123"


def test_report_data_roundtrip_json():
    report = Report(
        emulation_total_runtime=1.0,
        timestamp=123,
        entry_points=[],
        data={
            "deadbeef": DataArtifact(
                compression="zlib",
                encoding="base64",
                size=4,
                data=base64.b64encode(zlib.compress(b"data")).decode(),
            )
        },
    )

    restored = Report.model_validate_json(report.model_dump_json())

    assert decode_artifact(restored.data["deadbeef"]) == b"data"
