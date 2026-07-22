from assurance.evidence import EvidenceLog


def test_append_returns_seq_and_hash_and_verifies():
    log = EvidenceLog()
    e0 = log.append({"attack": "A1", "outcome": "PASS"})
    e1 = log.append({"attack": "A2", "outcome": "LEAK"})
    assert e0.seq == 0 and e1.seq == 1
    assert e1.this_hash and e1.prev_hash == e0.this_hash
    assert log.verify() is True


def test_tamper_is_detected():
    log = EvidenceLog()
    log.append({"attack": "A1", "outcome": "PASS"})
    log.append({"attack": "A2", "outcome": "PASS"})
    log.entries()[0].payload["outcome"] = "LEAK"
    assert log.verify() is False
