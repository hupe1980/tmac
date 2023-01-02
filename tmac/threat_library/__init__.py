import os
from typing import TYPE_CHECKING, List

from ..component import DataFormat, Component, Technology
from ..risk import ComponentRisk
from ..threat import CAPEC, ComponentThreat, ThreatLibrary
from ..user_story import ASVSCategory, UserStoryTemplate, UserStoryTemplateRepository

if TYPE_CHECKING:
    from ..model import Model


class CAPEC_62(ComponentThreat):
    def __init__(self) -> None:
        super().__init__(
            id="CAPEC-62",
            name="Cross-Site Request Forgery (CSRF)",
            category=CAPEC.SUBVERT_ACCESS_CONTROL,
            description="An attacker crafts malicious web links and distributes them (via web pages, email, etc.), typically in a targeted manner, hoping to induce users to click on the link and execute the malicious action against some third-party application. If successful, the action embedded in the malicious link will be processed and accepted by the targeted application with the users' privilege level. This type of attack leverages the persistence and implicit trust placed in user session cookies by many web applications today. In such an architecture, once the user authenticates to an application and a session cookie is created on the user's system, all following transactions for that session are authenticated using that cookie including potential actions initiated by an attacker and simply 'riding' the existing session cookie.",
            prerequisites=[],
            risk_text="Cross-Site Request Forgery (CSRF) risk at {{ component.name }} via {{ data_flow.name }} from {{ data_flow.source.name }}",
            cwe_ids=[352, 306, 664, 732, 1275],
            references=["https://capec.mitre.org/data/definitions/63.html"],
        )

    def apply(
        self, component: "Component", model: "Model"
    ) -> List["ComponentRisk"]:
        risks: List["ComponentRisk"] = list()

        if component.is_web_application is False:
            return []

        for flow in component.incoming_flows:
            if flow.is_web_access_protocol:
                risks.append(
                    ComponentRisk(
                        self, component=component, data_flow=flow, model=model
                    )
                )

        return risks


class CAPEC_63(ComponentThreat):
    def __init__(self) -> None:
        super().__init__(
            id="CAPEC-63",
            name="Cross-Site Scripting (XSS)",
            category=CAPEC.INJECT_UNEXPECTED_ITEMS,
            description="An adversary embeds malicious scripts in content that will be served to web browsers. The goal of the attack is for the target software, the client-side browser, to execute the script with the users' privilege level. An attack of this type exploits a programs' vulnerabilities that are brought on by allowing remote hosts to execute code and scripts. Web browsers, for example, have some simple security controls in place, but if a remote attacker is allowed to execute scripts (through injecting them in to user-generated content like bulletin boards) then these controls may be bypassed. Further, these attacks are very difficult for an end user to detect.",
            prerequisites=[
                "Target client software must be a client that allows scripting communication from remote hosts, such as a JavaScript-enabled Web Browser.",
            ],
            risk_text="Cross-Site Scripting (XSS) risk at {{ component.name }}",
            cwe_ids=[79, 20],
            references=["https://capec.mitre.org/data/definitions/63.html"],
        )

    def apply(
        self, component: "Component", model: "Model"
    ) -> List["ComponentRisk"]:
        risks: List["ComponentRisk"] = list()

        if component.is_web_application:
            risks.append(ComponentRisk(self, component=component, model=model))

        return risks

    def get_user_story_templates(
        self, repository: "UserStoryTemplateRepository", component: "Component"
    ) -> List["UserStoryTemplate"]:
        tpls = repository.get_by_cwe(*self.cwe_ids)
        
        result: List[UserStoryTemplate] = list()
        for tpl in tpls:
            if 20 in tpl.cwe_ids and tpl.sub_category == ASVSCategory.RESTFUL_WEB_SERVICE and (
                not DataFormat.JSON in component.accept_data_formats
                or not component.technology == Technology.WEB_SERVICE_REST
            ):
                continue
            elif 20 in tpl.cwe_ids and tpl.sub_category == ASVSCategory.SOAP_WEB_SERVICE and (
                not DataFormat.XML in component.accept_data_formats
                or not component.technology == Technology.WEB_SERVICE_SOAP
            ):
                 continue
            
            result.append(tpl)

        return result


class CAPEC_66(ComponentThreat):
    def __init__(self) -> None:
        super().__init__(
            id="CAPEC-66",
            name="SQL Injection",
            category=CAPEC.INJECT_UNEXPECTED_ITEMS,
            description="This attack exploits target software that constructs SQL statements based on user input. An attacker crafts input strings so that when the target software constructs SQL statements based on the input, the resulting SQL statement performs actions other than those the application intended. SQL Injection results from failure of the application to appropriately validate input.",
            prerequisites=[
                "SQL queries used by the application to store, retrieve or modify data.",
                "User-controllable input that is not properly validated by the application as part of SQL queries.",
            ],
            risk_text="SQL Injection risk at {{ component.name }} against database {{ data_flow.destination.name }} via {{ data_flow.name }}",
            cwe_ids=[89, 1286],
            references=["https://capec.mitre.org/data/definitions/66.html"],
        )

    def apply(
        self, component: "Component", model: "Model"
    ) -> List["ComponentRisk"]:
        risks: List["ComponentRisk"] = list()

        for flow in component.outgoing_flows:
            if flow.is_relational_database_protocol:
                risks.append(
                    ComponentRisk(
                        self, component=component, data_flow=flow, model=model
                    )
                )

        return risks


class CAPEC_126(ComponentThreat):
    def __init__(self) -> None:
        super().__init__(
            id="CAPEC-126",
            name="Path Traversal",
            category=CAPEC.MANIPULATE_DATA_STRUCTURES,
            description="An adversary uses path manipulation methods to exploit insufficient input validation of a target to obtain access to data that should be not be retrievable by ordinary well-formed requests. A typical variety of this attack involves specifying a path to a desired file together with dot-dot-slash characters, resulting in the file access API or function traversing out of the intended directory structure and into the root file system. By replacing or modifying the expected path information the access function or API retrieves the file desired by the attacker. These attacks either involve the attacker providing a complete path to a targeted file or using control characters (e.g. path separators (/ or \\) and/or dots (.)) to reach desired directories or files.",
            prerequisites=[
                "The attacker must be able to control the path that is requested of the target.",
                "The target must fail to adequately sanitize incoming paths.",
            ],
            risk_text="Path-Traversal risk at {{ component.name }} against filesystem {{ data_flow.destination.name }} via {{ data_flow.name }}",
            cwe_ids=[22],
            references=["https://capec.mitre.org/data/definitions/126.html"],
        )

    def apply(
        self, component: "Component", model: "Model"
    ) -> List["ComponentRisk"]:
        risks: List["ComponentRisk"] = list()

        for flow in component.outgoing_flows:
            if flow.destination.technology in [
                Technology.FILE_SERVER,
                Technology.LOCAL_FILE_SYSTEM,
            ]:
                risks.append(
                    ComponentRisk(
                        self, component=component, data_flow=flow, model=model
                    )
                )

        return risks


class CAPEC_664(ComponentThreat):
    def __init__(self) -> None:
        super().__init__(
            id="CAPEC-664",
            name="Server Side Request Forgery (SSRF)",
            category=CAPEC.SUBVERT_ACCESS_CONTROL,
            description="An adversary exploits improper input validation by submitting maliciously crafted input to a target application running on a server, with the goal of forcing the server to make a request either to itself, to web services running in the server's internal network, or to external third parties. If successful, the adversary's request will be made with the server's privilege level, bypassing its authentication controls. This ultimately allows the adversary to access sensitive data, execute commands on the server's network, and make external requests with the stolen identity of the server. Server Side Request Forgery attacks differ from Cross Site Request Forgery attacks in that they target the server itself, whereas CSRF attacks exploit an insecure user authentication mechanism to perform unauthorized actions on the user's behalf.",
            prerequisites=[
                "Server must be running a web application that processes HTTP requests.",
            ],
            risk_text="Server Side Request Forgery (SSRF) risk at {{ component.name }} requesting the target {{ data_flow.destination.name }} via {{ data_flow.name }}.",
            cwe_ids=[918, 20],
            references=["https://capec.mitre.org/data/definitions/664.html"],
        )

    def apply(
        self, component: "Component", model: "Model"
    ) -> List["ComponentRisk"]:
        risks: List["ComponentRisk"] = list()

        if component.is_client or component.technology in [Technology.LOAD_BALANCER]:
            return []

        for flow in component.outgoing_flows:
            if flow.is_web_access_protocol:
                risks.append(
                    ComponentRisk(
                        self, component=component, data_flow=flow, model=model
                    )
                )

        return risks


class CAPEC_676(ComponentThreat):
    def __init__(self) -> None:
        super().__init__(
            id="CAPEC-676",
            name="NoSQL Injection",
            category=CAPEC.INJECT_UNEXPECTED_ITEMS,
            description="An adversary targets software that constructs NoSQL statements based on user input or with parameters vulnerable to operator replacement in order to achieve a variety of technical impacts such as escalating privileges, bypassing authentication, and/or executing code.",
            prerequisites=[
                "Awareness of the technology stack being leveraged by the target application.",
                "NoSQL queries used by the application to store, retrieve, or modify data.",
                "User-controllable input that is not properly validated by the application as part of NoSQL queries.",
                "Target potentially susceptible to operator replacement attacks.",
            ],
            risk_text="NoSQL Injection risk at {{ component.name }} against database {{ data_flow.destination.name }} via {{ data_flow.name }}",
            cwe_ids=[943, 1286],
            references=["https://capec.mitre.org/data/definitions/676.html"],
        )

    def apply(
        self, component: "Component", model: "Model"
    ) -> List["ComponentRisk"]:
        risks: List["ComponentRisk"] = list()

        for flow in component.outgoing_flows:
            if flow.is_nosql_database_protocol:
                risks.append(
                    ComponentRisk(
                        self, component=component, data_flow=flow, model=model
                    )
                )

        return risks


DEFAULT_THREAT_LIBRARY = ThreatLibrary()

DEFAULT_THREAT_LIBRARY.add_threats(
    CAPEC_62(),
    CAPEC_63(),
    CAPEC_66(),
    CAPEC_126(),
    CAPEC_664(),
    CAPEC_676(),
)

DEFAULT_USER_STORY_TEMPLATE_REPOSITORY = UserStoryTemplateRepository.fromFile(
    os.path.dirname(__file__) + "/templates/user_story_templates.json"
)

__all__ = (
    "DEFAULT_THREAT_LIBRARY",
    "DEFAULT_USER_STORY_TEMPLATE_REPOSITORY",
)
