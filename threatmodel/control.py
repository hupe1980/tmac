from enum import Enum

class Control(Enum):
    """Controls implemented by/on and Element"""

    INPUT_BOUNDS_CHECKS = "input-bounds-checks"

    INPUT_SANITIZING = "input-sanitizing"

    INPUT_VALIDATION = "input-validation"

    Parameterization = "parameterization"
    """Parameterized queries or stored procedures"""

    SERVER_SIDE_INCLUDES_DEACTIVATION = "server-side-includes-deactivation"

    WAF = "waf"

    def __str__(self) -> str:
        return str(self.value)