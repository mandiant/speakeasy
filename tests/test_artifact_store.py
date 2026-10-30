import base64
import zlib

from speakeasy.artifacts import ArtifactStore
from speakeasy.report import DataArtifact


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
