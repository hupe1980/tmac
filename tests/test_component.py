from tmac import Machine

def test_machine():
    assert Machine("test") == "test"
    assert Machine.VIRTUAL == "virtual"