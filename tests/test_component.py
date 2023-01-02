from tmac import Machine


def test_machine() -> None:
    assert Machine("test") == "test"
    assert Machine.VIRTUAL == "virtual"
