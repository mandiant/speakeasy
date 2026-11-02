#!/usr/bin/env python3
"""
Generate the JSON schema of the speakeasy report.

The schema describes the JSON that ``Report.model_dump_json`` writes, so it
uses the serialization mode of pydantic: a ``HexInt`` field is a string.
``tests/test_report_schema.py`` fails when the file and the models differ.

Usage::

    python scripts/gen_report_schema.py
"""

import json
from pathlib import Path

from speakeasy.report import Report

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "speakeasy" / "resources" / "report.schema.json"


def main() -> None:
    schema = Report.model_json_schema(mode="serialization")
    SCHEMA_PATH.write_text(json.dumps(schema, indent=2) + "\n")


if __name__ == "__main__":
    main()
