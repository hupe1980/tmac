from typing import Optional

from ..component import Process, Technology
from ..data_flow import Authentication, DataFlow
from ..threat import AttackCategory, Threat, Threatlib, Likelihood, Impact, Risk, Treatment
from ..element import Element

# See https://capec.mitre.org/data/definitions/2000.html


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
        # Typeguard
        if not isinstance(target, Process):
            return None

        # Prerequisites
        if not target.is_using_environment_variables():
            return None

        return Risk(target, self, Impact.HIGH, Likelihood.VERY_LIKELY)


class CAPEC_62(Threat):
    def __init__(self) -> None:
        super().__init__(
            "CAPEC-62",
            "Cross Site Request Forgery",
            (DataFlow,),
            category=AttackCategory.SUBVERT_ACCESS_CONTROL,
            description="An attacker crafts malicious web links and distributes them (via web pages, email, etc.), typically in a targeted manner, hoping to induce users to click on the link and execute the malicious action against some third-party application. If successful, the action embedded in the malicious link will be processed and accepted by the targeted application with the users' privilege level. This type of attack leverages the persistence and implicit trust placed in user session cookies by many web applications today. In such an architecture, once the user authenticates to an application and a session cookie is created on the user's system, all following transactions for that session are authenticated using that cookie including potential actions initiated by an attacker and simply 'riding' the existing session cookie.",
            prerequisites=[],
            mitigations=[
                "Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.",
                "Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.",
                "Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.",
                "In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.",
            ],
            cwe_ids=[352, 306, 664, 732, 1275]
        )

    def apply(self, target: "Element") -> Optional["Risk"]:
        # Typeguard
        if not isinstance(target, DataFlow):
            return None

        # Prerequisites
        if not target.destination.is_web_application():
            return None

        return Risk(target.destination, self, Impact.MEDIUM, Likelihood.VERY_LIKELY)


class CAPEC_63(Threat):
    def __init__(self) -> None:
        super().__init__(
            "CAPEC-63",
            "Cross-Site Scripting (XSS)",
            (Process,),
            category=AttackCategory.INJECT_UNEXPECTED_ITEMS,
            description="An adversary embeds malicious scripts in content that will be served to web browsers. The goal of the attack is for the target software, the client-side browser, to execute the script with the users' privilege level. An attack of this type exploits a programs' vulnerabilities that are brought on by allowing remote hosts to execute code and scripts. Web browsers, for example, have some simple security controls in place, but if a remote attacker is allowed to execute scripts (through injecting them in to user-generated content like bulletin boards) then these controls may be bypassed. Further, these attacks are very difficult for an end user to detect.",
            prerequisites=[
                "Target client software must be a client that allows scripting communication from remote hosts, such as a JavaScript-enabled Web Browser.",
            ],
            mitigations=[
                "Design: Use browser technologies that do not allow client side scripting.",
                "Design: Utilize strict type, character, and encoding enforcement.",
                "Design: Server side developers should not proxy content via XHR or other means, if a http proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.",
                "Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.",
                "Implementation: Perform input validation for all remote content.",
                "Implementation: Perform output validation for all remote content.",
                "Implementation: Session tokens for specific host.",
                "Implementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.",
            ],
            cwe_ids=[79, 20]
        )

    def apply(self, target: "Element") -> Optional["Risk"]:
        # Typeguard
        if not isinstance(target, Process):
            return None

        # Prerequisites
        if not target.is_web_application():
            return None

        return Risk(target, self, Impact.MEDIUM, Likelihood.LIKELY)


class CAPEC_66(Threat):
    def __init__(self) -> None:
        super().__init__(
            "CAPEC-66",
            "SQL Injection",
            (DataFlow, ),
            category=AttackCategory.INJECT_UNEXPECTED_ITEMS,
            description="This attack exploits target software that constructs SQL statements based on user input. An attacker crafts input strings so that when the target software constructs SQL statements based on the input, the resulting SQL statement performs actions other than those the application intended. SQL Injection results from failure of the application to appropriately validate input.",
            prerequisites=[
                "SQL queries used by the application to store, retrieve or modify data.",
                "User-controllable input that is not properly validated by the application as part of SQL queries.",
            ],
            mitigations=[
                "Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as SQL content. Keywords such as UNION, SELECT or INSERT must be filtered in addition to characters such as a single-quote(') or SQL-comments (--) based on the context in which they appear.",
                "Use of parameterized queries or stored procedures - Parameterization causes the input to be restricted to certain domains, such as strings or integers, and any input outside such domains is considered invalid and the query fails. Note that SQL Injection is possible even in the presence of stored procedures if the eventual query is constructed dynamically.",
                "Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.",
            ],
            cwe_ids=[89, 1286],
        )

    def apply(self, target: "Element") -> Optional["Risk"]:
        # Typeguard
        if not isinstance(target, DataFlow):
            return None

        # Prerequisites
        if not target.is_relational_database_protocol():
            return None

        return Risk(target.source, self, Impact.HIGH, Likelihood.LIKELY)


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
        # Typeguard
        if not isinstance(target, Process):
            return None

        # Prerequisites
        # TODO

        return Risk(target, self, Impact.VERY_HIGH, Likelihood.VERY_LIKELY)


class CAPEC_101(Threat):
    def __init__(self) -> None:
        super().__init__(
            "CAPEC-101",
            "Server Side Include (SSI) Injection",
            (Process,),
            category=AttackCategory.INJECT_UNEXPECTED_ITEMS,
            description="An attacker can use Server Side Include (SSI) Injection to send code to a web application that then gets executed by the web server. Doing so enables the attacker to achieve similar results to Cross Site Scripting, viz., arbitrary code execution and information disclosure, albeit on a more limited scale, since the SSI directives are nowhere near as powerful as a full-fledged scripting language. Nonetheless, the attacker can conveniently gain access to sensitive files, such as password files, and execute shell commands.",
            prerequisites=[
                "A web server that supports server side includes and has them enabled",
                "User controllable input that can carry include directives to the web server",
            ],
            mitigations=[
                "Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them",
                "All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive",
                "Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead",
            ],
            cwe_ids=[97, 74, 20],
        )

    def apply(self, target: "Element") -> Optional["Risk"]:
        # Typeguard
        if not isinstance(target, Process):
            return None

        # Prerequisites
        if not target.is_web_application():
            return None

        return Risk(target, self, Impact.HIGH, Likelihood.LIKELY)


class CAPEC_102(Threat):
    def __init__(self) -> None:
        super().__init__(
            "CAPEC-102",
            "Session Sidejacking",
            (DataFlow, ),
            category=AttackCategory.SUBVERT_ACCESS_CONTROL,
            description="Session sidejacking takes advantage of an unencrypted communication channel between a victim and target system. The attacker sniffs traffic on a network looking for session tokens in unencrypted traffic. Once a session token is captured, the attacker performs malicious actions by using the stolen token with the targeted application to impersonate the victim. This attack is a specific method of session hijacking, which is exploiting a valid session token to gain unauthorized access to a target system or information. Other methods to perform a session hijacking are session fixation, cross-site scripting, or compromising a user or server machine and stealing the session token.",
            prerequisites=[
                "An attacker and the victim are both using the same WiFi network.",
                "The victim has an active session with a target system.",
                "The victim is not using a secure channel to communicate with the target system (e.g. SSL, VPN, etc.)",
                "The victim initiated communication with a target system that requires transfer of the session token or the target application uses AJAX and thereby periodically 'rings home' asynchronously using the session token.",
            ],
            mitigations=[
                "Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel.",
                "Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.",
            ],
            cwe_ids=[294, 522, 523, 319, 614],
        )

    def apply(self, target: "Element") -> Optional["Risk"]:
        # Typeguard
        if not isinstance(target, DataFlow):
            return None

        # Prerequisites
        if not target.authentication == Authentication.SESSION_ID:
            return None

        return Risk(target, self, Impact.HIGH, Likelihood.LIKELY)


class CAPEC_126(Threat):
    def __init__(self) -> None:
        super().__init__(
            "CAPEC-126",
            "Path Traversal",
            (Process, ),
            category=AttackCategory.MANIPULATE_DATA_STRUCTURES,
            description="An adversary uses path manipulation methods to exploit insufficient input validation of a target to obtain access to data that should be not be retrievable by ordinary well-formed requests. A typical variety of this attack involves specifying a path to a desired file together with dot-dot-slash characters, resulting in the file access API or function traversing out of the intended directory structure and into the root file system. By replacing or modifying the expected path information the access function or API retrieves the file desired by the attacker. These attacks either involve the attacker providing a complete path to a targeted file or using control characters (e.g. path separators (/ or \) and/or dots (.)) to reach desired directories or files.",
            prerequisites=[
                "The attacker must be able to control the path that is requested of the target.",
                "The target must fail to adequately sanitize incoming paths.",
            ],
            mitigations=[
                "Design: Configure the access control correctly.",
                "Design: Enforce principle of least privilege.",
                "Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.",
                "Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement.",
                "Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.",
                "Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.",
                "Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.",
                "Implementation: Perform input validation for all remote content, including remote and user-generated content.",
                "Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.",
                "Implementation: Use indirect references rather than actual file names.",
                "Implementation: Use possible permissions on file access when developing and deploying web applications.",
                "Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- using an allowlist approach.",
            ],
            cwe_ids=[294, 522, 523, 319, 614],
        )

    def apply(self, target: "Element") -> Optional["Risk"]:
        # Typeguard
        if not isinstance(target, Process):
            return None

        # Prerequisites
        if not target.technology in [Technology.FILE_SERVER, Technology.LOCAL_FILE_SYSTEM]:
            return None

        return Risk(target, self, Impact.MEDIUM, Likelihood.VERY_LIKELY)


class CAPEC_676(Threat):
    def __init__(self) -> None:
        super().__init__(
            "CAPEC-676",
            "NoSQL Injection",
            (DataFlow, ),
            category=AttackCategory.INJECT_UNEXPECTED_ITEMS,
            description="An adversary targets software that constructs NoSQL statements based on user input or with parameters vulnerable to operator replacement in order to achieve a variety of technical impacts such as escalating privileges, bypassing authentication, and/or executing code.",
            prerequisites=[
                "Awareness of the technology stack being leveraged by the target application.",
                "NoSQL queries used by the application to store, retrieve, or modify data.",
                "User-controllable input that is not properly validated by the application as part of NoSQL queries.",
                "Target potentially susceptible to operator replacement attacks.",
            ],
            mitigations=[
                "Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as relevant NoSQL and JavaScript content. NoSQL-specific keywords, such as $ne, $eq or $gt for MongoDB, must be filtered in addition to characters such as a single-quote(') or semicolons (;) based on the context in which they appear. Validation should also extend to expected types.",
                "If possible, leverage safe APIs (e.g., PyMongo and Flask-PyMongo for Python and MongoDB) for queries as opposed to building queries from strings.",
                "Ensure the most recent version of a NoSQL database and it's corresponding API are used by the application.",
                "Use of custom error pages - Adversaries can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.",
                "Exercise the principle of Least Privilege with regards to application accounts to minimize damage if a NoSQL injection attack is successful.",
                "If using MongoDB, disable server-side JavaScript execution and leverage a sanitization module such as 'mongo-sanitize'.",
                "If using PHP with MongoDB, ensure all special query operators (starting with $) use single quotes to prevent operator replacement attacks.",
                "Additional mitigations will depend on the NoSQL database, API, and programming language leveraged by the application.",
            ],
            cwe_ids=[943, 1286],
        )

    def apply(self, target: "Element") -> Optional["Risk"]:
        # Typeguard
        if not isinstance(target, DataFlow):
            return None

        # Prerequisites
        if not target.is_nosql_database_protocol():
            return None

        return Risk(target.source, self, Impact.HIGH, Likelihood.LIKELY)


DEFAULT_THREATLIB = Threatlib()

DEFAULT_THREATLIB.add_threats(
    CAPEC_10(),
    CAPEC_62(),
    CAPEC_63(),
    CAPEC_66(),
    CAPEC_100(),
    CAPEC_101(),
    CAPEC_102(),
    CAPEC_126(),
    CAPEC_676(),
)

__all__ = (
    "DEFAULT_THREATLIB"
    "CAPEC_10",
    "CAPEC_62",
    "CAPEC_63",
    "CAPEC_66",
    "CAPEC_100",
    "CAPEC_101",
    "CAPEC_102",
    "CAPEC_126",
    "CAPEC_676",
)
