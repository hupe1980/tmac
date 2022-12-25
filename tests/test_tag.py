from threatmodel import TagMixin


def test_tag_mixin() -> None:
    class A(TagMixin):
        pass
    class B(TagMixin):
        pass

    a = A()
    b = B()

    a.add_tags("a", "b", "c")
    b.add_tags("x", "y", "z")

    assert a.has_tag("a")
    assert a.has_tag("z") is False
