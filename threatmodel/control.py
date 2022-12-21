from enum import Enum


class classproperty(object):
    def __init__(self, f):
        self.f = f
    def __get__(self, obj, owner):
        return self.f(owner)

class Control(Enum):
    """Controls implemented by/on and Element"""

    @classproperty
    def list(cls):
        return list(map(lambda c: f"{c.name}: {c.value}", cls)) # type: ignore

    BOUNDS_CHECKING = "Bounds Checking"

    INPUT_SANITIZING = "Input Sanitizing"

    INPUT_VALIDATION = "Input Validation"

    PARAMETERIZATION = "Parameterization"
    """Parameterized queries or stored procedures"""

    AVOID_SERVER_SIDE_INCLUDES = "Avoid Server-Side Includes (SSI)"

    AVOID_USING_COMMAND_INTERPRETERS = "Avoid Using Command Interpreters"

    WAF = "waf"

    CSRF_TOKEN = "CSRF Token"

    RE_AUTHENTICATION = "Re-Authentication"
    
    ONE_TIME_TOKEN =  "One-time Token"

    CAPTCHA = "CAPTCHA"
    

    def __str__(self) -> str:
        return str(self.value)