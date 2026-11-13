import hashlib
import zlib
from base64 import b64decode, b64encode
from collections.abc import Collection

from speakeasy.report import ArtifactCompression, ArtifactEncoding, DataArtifact

MAX_EMBEDDED_FILE_SIZE = 10 * 1024 * 1024


class ArtifactStore:
    def __init__(self):
        self._artifacts: dict[str, DataArtifact] = {}

    def put_bytes(self, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        if digest not in self._artifacts:
            compressed = zlib.compress(data)
            self._artifacts[digest] = DataArtifact(
                compression=ArtifactCompression.ZLIB,
                encoding=ArtifactEncoding.BASE64,
                size=len(data),
                data=b64encode(compressed).decode("ascii"),
            )
        return digest

    def get_bytes(self, artifact_ref: str) -> bytes:
        return zlib.decompress(b64decode(self._artifacts[artifact_ref].data))

    def to_report_data(self, refs: Collection[str]) -> dict[str, DataArtifact]:
        """Get the payloads of ``refs``, in the order of storage. The store leaves out the payloads of other keys."""
        return {ref: artifact for ref, artifact in self._artifacts.items() if ref in refs}
