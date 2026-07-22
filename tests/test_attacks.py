from assurance.attacks import BATTERY, Attack
from assurance.frameworks import CONTROLS


def test_battery_is_nonempty_and_typed():
    assert len(BATTERY) == 8
    assert all(isinstance(a, Attack) for a in BATTERY)


def test_every_attack_control_is_known():
    for a in BATTERY:
        for cid in a.controls:
            assert cid in CONTROLS, f"{a.id} references unknown control {cid}"


def test_attack_ids_unique():
    ids = [a.id for a in BATTERY]
    assert len(ids) == len(set(ids))
