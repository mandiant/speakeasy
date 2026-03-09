import hashlib
import zlib
from base64 import b64decode, b64encode

from speakeasy.report import DataArtifact

MAX_EMBEDDED_FILE_SIZE = 10 * 1024 * 1024


class ArtifactStore:
    def __init__(self):
        self._artifacts: dict[str, DataArtifact] = {}

    def put_bytes(self, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        if digest not in self._artifacts:
            compressed = zlib.compress(data)
            self._artifacts[digest] = DataArtifact(
                compression="zlib",
                encoding="base64",
                size=len(data),
                data=b64encode(compressed).decode("ascii"),
            )
        return digest

    def get_bytes(self, artifact_ref: str) -> bytes:
        artifact = self._artifacts[artifact_ref]
        if artifact.compression != "zlib":
            raise ValueError(f"Unsupported compression: {artifact.compression}")
        if artifact.encoding != "base64":
            raise ValueError(f"Unsupported encoding: {artifact.encoding}")
        return zlib.decompress(b64decode(artifact.data))

    def to_report_data(self) -> dict[str, DataArtifact]:
        return dict(self._artifacts)
