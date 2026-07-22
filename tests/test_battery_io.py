import pytest

from assurance.battery_io import (
    parse_battery, load_battery_json, default_battery_json, attack_to_dict)
from assurance.attacks import BATTERY, Attack


def test_roundtrip_default_battery():
    loaded = load_battery_json(default_battery_json())
    assert len(loaded) == len(BATTERY)
    assert all(isinstance(a, Attack) for a in loaded)
    assert loaded[0].id == BATTERY[0].id
    assert loaded[0].controls == BATTERY[0].controls


def test_parse_minimal_valid():
    recs = [{"id": "C1", "description": "d", "role": "analyst", "prompt": "p",
             "expectation": "DENY", "controls": ["OWASP-LLM06"]}]
    b = parse_battery(recs)
    assert b[0].id == "C1" and b[0].tier3_allowed is False and b[0].setup_provider is None


def test_optional_fields_carried():
    recs = [{"id": "C1", "description": "d", "role": "analyst", "prompt": "p",
             "expectation": "NO_DIRECT_ID", "controls": ["HIPAA-164.514-DIRECT"],
             "setup_provider": "PRV1000", "tier3_allowed": True}]
    b = parse_battery(recs)
    assert b[0].setup_provider == "PRV1000" and b[0].tier3_allowed is True


def test_unknown_control_rejected():
    recs = [{"id": "C1", "description": "d", "role": "analyst", "prompt": "p",
             "expectation": "DENY", "controls": ["NOPE-999"]}]
    with pytest.raises(ValueError):
        parse_battery(recs)


def test_missing_field_rejected():
    with pytest.raises(ValueError):
        parse_battery([{"id": "C1", "role": "analyst"}])


def test_duplicate_id_rejected():
    recs = [{"id": "C1", "description": "d", "role": "a", "prompt": "p",
             "expectation": "DENY", "controls": []},
            {"id": "C1", "description": "d", "role": "a", "prompt": "p",
             "expectation": "DENY", "controls": []}]
    with pytest.raises(ValueError):
        parse_battery(recs)


def test_bad_json_rejected():
    with pytest.raises(ValueError):
        load_battery_json("{not valid json")


def test_empty_battery_rejected():
    with pytest.raises(ValueError):
        parse_battery([])
