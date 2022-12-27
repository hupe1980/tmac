import pytest 
from tmac import Construct


@pytest.fixture
def root() -> "Construct":
    return Construct(None, "")
