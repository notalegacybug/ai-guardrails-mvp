from assurance.corpus import build_labeled_corpus, LabeledSample, PiiSpan


def test_corpus_is_deterministic():
    a = build_labeled_corpus(7)
    b = build_labeled_corpus(7)
    assert [(s.text, tuple(s.true_pii)) for s in a] == \
           [(s.text, tuple(s.true_pii)) for s in b]


def test_has_positives_and_negatives():
    c = build_labeled_corpus(7)
    assert any(s.true_pii for s in c)          # at least one positive
    assert any(not s.true_pii for s in c)      # at least one clean negative


def test_labeled_values_actually_appear_in_text():
    for s in build_labeled_corpus(7):
        for span in s.true_pii:
            assert span.value in s.text, (span, s.text)


def test_positives_include_name_and_ssn_labels():
    types = {span.pii_type for s in build_labeled_corpus(7) for span in s.true_pii}
    assert "NAME" in types and "SSN" in types and "ZIP" in types and "MRN" in types
