import pytest
from tmac.node import Construct, kebab_case


def test_special_root_construct(root: "Construct") -> None:
    node = root.node
    assert node.id == ""
    assert node.scope is None
    assert len(node.children) == 0


def test_no_empty_id_by_none_root_constructs(root: "Construct") -> None:
    with pytest.raises(ValueError):
        Construct(root, "")

def test_kebab() -> None:
    assert kebab_case("Foo Bar") == "foo-bar"
    assert kebab_case("foo-bar") == "foo-bar"
    assert kebab_case("FooBar") == "foo-bar"
