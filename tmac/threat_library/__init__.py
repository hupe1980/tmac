import os
from typing import TYPE_CHECKING, List, Optional

from ..risk import Risk
from ..threat import ComponentThreat, Stride, ThreatLibrary
from ..user_story import UserStoryTemplateRepository, UserStoryTemplate

if TYPE_CHECKING:
    from ..component import TechnicalComponent
    from ..model import Model


class CAPEC_63(ComponentThreat):
    def __init__(self) -> None:
        super().__init__(
            id="CAPEC-63",
            name="Cross-Site Scripting (XSS)",
            risk_text="Cross-Site Scripting (XSS) risk at {{ component.name }}",
            stride=Stride.TAMPERING,
            cwe_ids=[79, 20],
        )

    def apply(self, component: "TechnicalComponent", model: "Model") -> Optional["Risk"]:
        if component.is_web_application:
            return Risk(component, self, model) 
        return None


class CAPEC_66(ComponentThreat):
    def __init__(self) -> None:
        super().__init__(
            id="CAPEC-66",
            name="SQL Injection",
            risk_text="SQL Injection risk at {{ component.name }}",
            stride=Stride.TAMPERING,
            cwe_ids=[89, 1286],
        )

    def apply(self, component: "TechnicalComponent", model: "Model") -> Optional["Risk"]:
        for flow in component.outgoing_flows:
            if flow.is_relational_database_protocol:
                return Risk(component, self, model)  # TODO Rist List

        return None


class CAPEC_664(ComponentThreat):
    def __init__(self) -> None:
        super().__init__(
            id="CAPEC-664",
            name="Server Side Request Forgery (SSRF)",
            risk_text="Server Side Request Forgery (SSRF) risk at {{ component.name }}",
            stride=Stride.INFORMATION_DISCLOSURE,
            cwe_ids=[918, 20],
        )

    def apply(self, component: "TechnicalComponent", model: "Model") -> Optional["Risk"]:
        for flow in component.outgoing_flows:
            if flow.is_web_access_protocol:
                return Risk(component, self, model)  # TODO Rist List

        return None


class CAPEC_676(ComponentThreat):
    def __init__(self) -> None:
        super().__init__(
            id="CAPEC-676",
            name="NoSQL Injection",
            risk_text="NoSQL Injection risk at {{ component.name }}",
            stride=Stride.TAMPERING,
            cwe_ids=[943, 1286],
        )

    def apply(self, component: "TechnicalComponent", model: "Model") -> Optional["Risk"]:
        for flow in component.outgoing_flows:
            if flow.is_nosql_database_protocol:
                return Risk(component, self, model)  # TODO Rist List

        return None


DEFAULT_THREAT_LIBRARY = ThreatLibrary()

DEFAULT_THREAT_LIBRARY.add_threats(
    CAPEC_63(),
    CAPEC_66(),
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
