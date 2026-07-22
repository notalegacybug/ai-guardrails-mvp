from assurance.frameworks import CONTROLS, get, all_controls


def test_expected_controls_present():
    expected = {
        "HIPAA-164.514-DIRECT", "HIPAA-164.514-QUASI", "HIPAA-MIN-CELL",
        "OWASP-LLM01", "OWASP-LLM06", "NIST-MEASURE-2.7", "ACCESS-RBAC",
    }
    assert expected <= set(CONTROLS)


def test_get_returns_control_with_framework():
    c = get("HIPAA-MIN-CELL")
    assert c.framework == "HIPAA Safe Harbor"
    assert "cell" in c.title.lower()


def test_all_controls_returns_list():
    assert len(all_controls()) == len(CONTROLS)
