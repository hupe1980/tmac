from tmac.id import kebab_case


def test_kebab() -> None:
    assert kebab_case("Foo Bar") == "foo-bar"
    assert kebab_case("foo-bar") == "foo-bar"
    assert kebab_case("FooBar") == "foo-bar"