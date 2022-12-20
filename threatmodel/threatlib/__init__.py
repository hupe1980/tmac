from typing import Optional

from ..threatmodel import Element, Risk, Threat, Threatlib, Likelihood, Severity, TechnicalAsset

DEFAULT_THREATLIB = Threatlib()


class INP01(Threat):
    def __init__(self) -> None:
        super().__init__(
            "INP01",
            (TechnicalAsset,),
            description="Buffer Overflow via Environment Variables",
            details="This attack pattern involves causing a buffer overflow through manipulation of environment variables. Once the attacker finds that they can modify an environment variable, they may try to overflow associated buffers. This attack leverages implicit trust often placed in environment variables.",
            likelihood=Likelihood.VERY_LIKELY,
            severity=Severity.HIGH,
            prerequisites="The application uses environment variables. An environment variable exposed to the user is vulnerable to a buffer overflow. The vulnerable environment variable uses untrusted data. Tainted data used in the environment variables is not properly validated. For instance boundary checking is not done before copying the input data to a buffer.",
            mitigations="Do not expose environment variable to the user.Do not use untrusted data in your environment variables. Use a language or compiler that performs automatic bounds checking. There are tools such as Sharefuzz [R.10.3] which is an environment variable fuzzer for Unix that support loading a shared library. You can use Sharefuzz to determine if you are exposing an environment variable vulnerable to buffer overflow.",
            example="Attack Example: Buffer Overflow in $HOME A buffer overflow in sccw allows local users to gain root access via the $HOME environmental variable. Attack Example: Buffer Overflow in TERM A buffer overflow in the rlogin program involves its consumption of the TERM environmental variable.",
            references="https://capec.mitre.org/data/definitions/10.html, CVE-1999-0906, CVE-1999-0046, http://cwe.mitre.org/data/definitions/120.html, http://cwe.mitre.org/data/definitions/119.html, http://cwe.mitre.org/data/definitions/680.html"
        )

    def apply(self, target: "Element") -> Optional["Risk"]:
        if not isinstance(target, TechnicalAsset):
            return None

        if target.environment_variables is True and target.controls.sanitizesInput is False and target.controls.checksInputBounds is False:
            return Risk(target, self)

        return None


class INP02(Threat):
    def __init__(self) -> None:
        super().__init__(
            "INP02",
            (TechnicalAsset,),
            description="Overflow Buffers",
            details="Buffer Overflow attacks target improper or missing bounds checking on buffer operations, typically triggered by input injected by an adversary. As a consequence, an adversary is able to write past the boundaries of allocated buffer regions in memory, causing a program crash or potentially redirection of execution as per the adversaries' choice.",
            likelihood=Likelihood.VERY_LIKELY,
            severity=Severity.CRITICAL,
            prerequisites="Targeted software performs buffer operations.Targeted software inadequately performs bounds-checking on buffer operations.Adversary has the capability to influence the input to buffer operations.",
            mitigations="Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.",
            example="The most straightforward example is an application that reads in input from the user and stores it in an internal buffer but does not check that the size of the input data is less than or equal to the size of the buffer. If the user enters excessive length data, the buffer may overflow leading to the application crashing, or worse, enabling the user to cause execution of injected code.Many web servers enforce security in web applications through the use of filter plugins. An example is the SiteMinder plugin used for authentication. An overflow in such a plugin, possibly through a long URL or redirect parameter, can allow an adversary not only to bypass the security checks but also execute arbitrary code on the target web server in the context of the user that runs the web server process.",
            references="https://capec.mitre.org/data/definitions/100.html, http://cwe.mitre.org/data/definitions/120.html, http://cwe.mitre.org/data/definitions/119.html, http://cwe.mitre.org/data/definitions/680.html",
        )

    def apply(self, target: "Element") -> Optional["Risk"]:
        if not isinstance(target, TechnicalAsset):
            return None

        if target.controls.checksInputBounds is False:
            return Risk(target, self)

        return None


DEFAULT_THREATLIB.add_threats(INP01(), INP02())

__all__ = (
    "DEFAULT_THREATLIB"
)
