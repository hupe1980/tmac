import pytest
from tmac import Score


def test_score() -> None:
    assert Score(0) == 0
    assert Score(100) == 100


def test_score_raises_value_error() -> None:
    with pytest.raises(ValueError):
        Score(101)

    with pytest.raises(ValueError):
        Score(-1)


def test_score_none() -> None:
    assert Score.NONE == 0


def test_score_comparaison() -> None:
    assert Score.LOW < Score.HIGH
    assert Score.HIGH > Score.LOW
    assert Score.MEDIUM == Score.MEDIUM


def test_score_str() -> None:
    assert str(Score.NONE) == "None"
    assert str(Score.LOW) == "Low"
