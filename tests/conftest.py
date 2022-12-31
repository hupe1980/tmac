import pytest 
from tmac import Construct, Model

@pytest.fixture
def root() -> "Construct":
    return Construct(None, "")

@pytest.fixture
def model() -> "Model":
    return Model("Model")
