from typing import Optional

from ..threatmodel import AttackCategory, Element, Risk, Threat, Threatlib, Likelihood, Impact, Controls, Process


class CAPEC_10(Threat):
    def __init__(self) -> None:
        super().__init__(
            "CAPEC-10",
            "Buffer Overflow via Environment Variables",
            (Process,),
            category=AttackCategory.MANIPULATE_DATA_STRUCTURES,
            description="This attack pattern involves causing a buffer overflow through manipulation of environment variables. Once the attacker finds that they can modify an environment variable, they may try to overflow associated buffers. This attack leverages implicit trust often placed in environment variables.",
            prerequisites=[
                "The application uses environment variables.",
                "An environment variable exposed to the user is vulnerable to a buffer overflow.",
                "The vulnerable environment variable uses untrusted data.",
                "Tainted data used in the environment variables is not properly validated. For instance boundary checking is not done before copying the input data to a buffer.",
            ],
            mitigations=[
                "Do not expose environment variable to the user.",
                "Do not use untrusted data in your environment variables.",
                "Use a language or compiler that performs automatic bounds checking.",
                "There are tools such as Sharefuzz [R.10.3] which is an environment variable fuzzer for Unix that support loading a shared library. You can use Sharefuzz to determine if you are exposing an environment variable vulnerable to buffer overflow.",
            ],
            cwe_ids=[120, 302, 118, 119, 74, 99, 20, 680, 733, 697]
        )

    def apply(self, target: "Element") -> Optional["Risk"]:
        if not isinstance(target, Process):
            return None

        if target.environment_variables is True and target.has_control(Controls.INPUT_SANITIZING) is False and target.has_control(Controls.INPUT_BOUNDS_CHECKS) is False:
            return Risk(target, self, Impact.HIGH, Likelihood.VERY_LIKELY)

        return None


class CAPEC_100(Threat):
    def __init__(self) -> None:
        super().__init__(
            "CAPEC-100",
            "Overflow Buffers",
            (Process,),
            category=AttackCategory.MANIPULATE_DATA_STRUCTURES,
            description="Buffer Overflow attacks target improper or missing bounds checking on buffer operations, typically triggered by input injected by an adversary. As a consequence, an adversary is able to write past the boundaries of allocated buffer regions in memory, causing a program crash or potentially redirection of execution as per the adversaries' choice.",
            prerequisites=[
                "Targeted software performs buffer operations.",
                "Targeted software inadequately performs bounds-checking on buffer operations.",
                "Adversary has the capability to influence the input to buffer operations.",
            ],
            mitigations=[
                "Use a language or compiler that performs automatic bounds checking.",
                "Use secure functions not vulnerable to buffer overflow.",
                "If you have to use dangerous functions, make sure that you do boundary checking.",
                "Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.",
                "Use OS-level preventative functionality. Not a complete solution.",
                "Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.",
            ],
            cwe_ids=[120, 119, 131, 129, 805, 680]
        )

    def apply(self, target: "Element") -> Optional["Risk"]:
        if not isinstance(target, Process):
            return None

        if not target.has_control(Controls.INPUT_BOUNDS_CHECKS):
            return Risk(target, self, Impact.VERY_HIGH, Likelihood.VERY_LIKELY)

        return None


DEFAULT_THREATLIB = Threatlib()

DEFAULT_THREATLIB.add_threats(CAPEC_10(), CAPEC_100())

__all__ = (
    "DEFAULT_THREATLIB"
)
