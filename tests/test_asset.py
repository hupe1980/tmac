from tmac import Asset, Model, Score


def test_average_asset_score(model: "Model") -> None:
    foo = Asset(
        model,
        "Foo",
        confidentiality=Score(20),
        integrity=Score(10),
        availability=Score(60),
    )

    assert foo.average_score == 30
