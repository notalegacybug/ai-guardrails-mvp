from assurance.detector import RegexDetector, detect_in_response

D = RegexDetector()


def test_detects_ssn():
    dets = D.detect("member ssn 123-45-6789 on file")
    assert any(x.pii_type == "SSN" and x.value == "123-45-6789" for x in dets)


def test_full_zip_detected_generalized_not():
    assert any(x.pii_type == "ZIP" for x in D.detect("residence 75201"))
    assert not any(x.pii_type == "ZIP" for x in D.detect("residence 752XX"))


def test_long_digit_run_is_not_a_zip():
    assert not any(x.pii_type == "ZIP" for x in D.detect("id 123456789 end"))


def test_mrn_detected():
    assert any(x.pii_type == "MRN" and x.value == "M123456"
               for x in D.detect("record M123456 pulled"))


def test_email_and_full_date():
    types = {x.pii_type for x in D.detect("mail a.b@care.org dos 2025-03-14")}
    assert "EMAIL" in types and "DATE" in types


def test_bare_year_is_not_a_date():
    assert not any(x.pii_type == "DATE" for x in D.detect("seen in 2025 once"))


def test_ssn_yields_single_typed_detection():
    dets = D.detect("123-45-6789")
    assert len(dets) == 1 and dets[0].pii_type == "SSN"


def test_detect_in_response_scans_nested_values():
    resp = {"status": "ok", "rows": [{"note": "ssn 123-45-6789"}]}
    assert any(x.pii_type == "SSN" for x in detect_in_response(D, resp))


def test_non_string_input_is_coerced():
    assert D.detect(None) == []  # str(None) == "None": no matches, no crash
