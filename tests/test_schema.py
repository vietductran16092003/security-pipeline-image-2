import json
from pathlib import Path

import jsonschema
import pytest

from conftest import make_report, vuln as _vuln


def vuln(*a, **k):
    return _vuln(*a, reason="r", recommendation="r", **k)

SCHEMA = json.loads((Path(__file__).resolve().parent.parent / "schema.json").read_text(encoding="utf-8"))


def test_report_validates():
    jsonschema.validate(json.loads(make_report([vuln("A"), vuln("B", "P2", fixed=None)]).to_json()), SCHEMA)


def test_missing_priority_invalid():
    data = json.loads(make_report([vuln("A")]).to_json())
    data["sections"][2]["findings"][0]["priority"] = None
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, SCHEMA)


def test_bad_section_status_invalid():
    data = json.loads(make_report([]).to_json())
    data["sections"][0]["status"] = "ok"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, SCHEMA)


def test_agent_annotations_allowed():
    data = json.loads(make_report([vuln("A")]).to_json())
    data["sections"][2]["findings"][0].update(exploitable="Exploitable", assessed_by="severity_agent")
    jsonschema.validate(data, SCHEMA)
