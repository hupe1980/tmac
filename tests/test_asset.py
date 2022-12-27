from tmac import Asset, Construct, Score


def test_average_asset_score(root: "Construct") -> None:
    foo = Asset(
        root,
        "Foo",
        confidentiality=Score(20),
        integrity=Score(10),
        availability=Score(60),
    )

    assert foo.average_score == 30
