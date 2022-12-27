from typing import Any

class ScoreMeta(type):
    def __init__(cls, *args: Any) -> None:
        cls.NONE: "Score" = cls(0)
        cls.VERY_LOW: "Score" = cls(20)
        cls.LOW: "Score" = cls(40)
        cls.MEDIUM: "Score" = cls(60)
        cls.HIGH: "Score" = cls(80)
        cls.VERY_HIGH: "Score" = cls(100)

class Score(int, metaclass=ScoreMeta):
    def __new__(cls, value: int) -> "Score":
        if value < 0 or value > 100:
            raise ValueError(f"Score must be betwenn 0 and 100: {value}")
        return super().__new__(cls, value)

    def __str__(self) -> str:
        if self == 0:
            return "None"
        if self > 0 and self <= 20:
            return "Very Low"
        if self > 20 and self <= 40:
            return "Low"
        if self > 40 and self <= 60:
            return "Medium"
        if self > 60 and self <= 80:
            return "High"
        if self > 80:
            return "Very High"
        return NotImplemented
    

