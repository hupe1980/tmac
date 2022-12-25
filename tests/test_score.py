import pytest
from threatmodel import Score

def test_score():
    assert Score(0) == 0
    assert Score(100) == 100

def test_score_raise_value_error():
    with pytest.raises(ValueError):
        Score(101)

    with pytest.raises(ValueError):
        Score(-1)

def test_score_none():
    assert Score.NONE == 0

def test_score_comparaison():
    assert Score.LOW < Score.HIGH
    assert Score.HIGH > Score.LOW
    assert Score.MEDIUM == Score.MEDIUM

def test_score_str():
    assert str(Score.NONE) == "None"
    assert str(Score.LOW) == "Low"