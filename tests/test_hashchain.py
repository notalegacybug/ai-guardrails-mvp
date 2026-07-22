from common.hashchain import HashChain


def test_append_and_verify_intact():
    chain = HashChain()
    chain.append({"action": "A"})
    chain.append({"action": "B"})
    assert chain.verify() is True
    assert [e.seq for e in chain.entries()] == [0, 1]


def test_tamper_breaks_chain():
    chain = HashChain()
    chain.append({"action": "A"})
    chain.append({"action": "B"})
    # Mutate a past entry's payload after the fact.
    chain.entries()[0].payload["action"] = "TAMPERED"
    assert chain.verify() is False


def test_first_entry_links_to_genesis():
    chain = HashChain()
    e = chain.append({"x": 1})
    assert e.prev_hash == HashChain.GENESIS
    assert e.this_hash and e.this_hash != HashChain.GENESIS
