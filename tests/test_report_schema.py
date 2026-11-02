import json
from pathlib import Path

import speakeasy
from speakeasy.report import Report

SCHEMA_PATH = Path(speakeasy.__file__).parent / "resources" / "report.schema.json"


def test_report_schema_file_matches_models():
    shipped = json.loads(SCHEMA_PATH.read_text())
    assert shipped == Report.model_json_schema(mode="serialization"), (
        "speakeasy/resources/report.schema.json differs from the report models; run `just gen-report-schema`"
    )
