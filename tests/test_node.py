import pytest
from threatmodel import Construct


@pytest.fixture
def root() -> "Construct":
    return Construct(None, "")


def test_special_root_construct(root: "Construct") -> None:
    node = root.node
    assert node.id == ""
    assert node.scope is None
    assert len(node.children) == 0


def test_no_empty_id_by_none_root_constructs(root: "Construct") -> None:
    with pytest.raises(ValueError):
        Construct(root, "")
