from abc import ABC, abstractmethod
from enum import Enum
from typing import (
    Callable,
    Dict,
    List,
    MutableMapping,
    Iterator,
    Optional,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from .component import TechnicalComponent
    from .model import Model
    from .risk import Risk
    from .user_story import UserStoryTemplate, UserStoryTemplateRepository


class Stride(Enum):
    SPOOFING = "spoofing"
    """Involves illegally accessing and then using another user's authentication information, such as username and password."""

    TAMPERING = "tampering"
    """Involves the malicious modification of data. Examples include unauthorized changes made to persistent data, such as that held in a database, and the alteration of data as it flows between two computers over an open network, such as the Internet."""

    REPUDIATION = "repudiation"
    """Associated with users who deny performing an action without other parties having any way to prove otherwise."""

    INFORMATION_DISCLOSURE = "information-disclosure"
    """Involves the exposure of information to individuals who are not supposed to have access to it."""

    DENIAL_OF_SERVICE = "denial-of-service"
    """Denial of service (DoS) attacks deny service to valid users."""

    ELEVATION_OF_PRIVILEGE = "elevation-of-privilege"
    """An unprivileged user gains privileged access and thereby has sufficient access to compromise or destroy the entire system. Elevation of privilege threats include those situations in which an attacker has effectively penetrated all system defenses and become part of the trusted system itself, a dangerous situation indeed."""

    def __str__(self) -> str:
        return str(self.value)

class Linddum(Enum):
    LINKABILITY = "linkability"
    """An adversary is able to link two items of interest without knowing the identity of the data subject(s) involved."""
    
    IDENTIFIABILITY = "identifiability"
    """An adversary is able to identify a data subject from a set of data subjects through an item of interest."""
    
    NON_REPUDIATION = "non-repudiation"
    """The data subject is unable to deny a claim (e.g., having performed an action, or sent a request)."""
    
    DETECTABILITY = "detectability"
    """An adversary is able to distinguish whether an item of interest about a data subject exists or not, regardless of being able to read the contents itself."""
    
    DISCLOSURE_OF_INFORMATION = "disclosure-of-information"
    """An adversary is able to learn the content of an item of interest about a data subject."""
   
    UNAWARENESS = "unawareness"
    """The data subject is unaware of the collection, processing, storage, or sharing activities (and corresponding purposes) of the data subject's personal data."""
    
    NON_COMPLIANCE = "non-compliance"
    """The processing, storage, or handling of personal data is not compliant with legislation, regulation, and/or policy."""


class ThreatLibrary(MutableMapping[str, "BaseThreat"]):
    """Represents a threat library"""

    def __init__(self) -> None:
        self.excludes: List[str] = list()  # TODO
        self._lib: Dict[str, "BaseThreat"] = dict()
        self.after_apply_hook: Optional[Callable[[List["Risk"]], None]] = None

    def add_threats(self, *threats: "BaseThreat") -> None:
        for threat in threats:
            self._lib[threat.id] = threat

    def apply(self, model: "Model", component: Optional["TechnicalComponent"]) -> List["Risk"]:
        risks: List["Risk"] = list()

        for item in self.values():
            if item.id in self.excludes:
                continue

            if isinstance(item, ComponentThreat) and component is not None:
                if item.is_applicable(component):
                    risk = item.apply(component, model)
                    if risk is not None:
                        risks.append(risk)

            if isinstance(item, ModelThreat):
                risk = item.apply(model)
                if risk is not None:
                    risks.append(risk)

        if self.after_apply_hook is not None:
            self.after_apply_hook(risks)

        return risks

    def __getitem__(self, id: str) -> "BaseThreat":
        return self._lib[id]

    def __setitem__(self, id: str, value: "BaseThreat") -> None:
        self._lib[id] = value

    def __delitem__(self, id: str) -> None:
        del self._lib[id]

    def __iter__(self) -> Iterator[str]:
        return iter(self._lib)

    def __len__(self) -> int:
        return len(self._lib)


class BaseThreat(ABC):
    def __init__(
        self, id: str, name: str, risk_text: str, stride: Stride, cwe_ids: List[int] = []
    ) -> None:
        self._id = id
        self._name = name
        self.risk_text = risk_text
        self.stride = stride
        self.cwe_ids = cwe_ids

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return self._name


class ModelThreat(BaseThreat):
    def __init__(
        self, id: str, name: str, risk_text: str, stride: Stride, cwe_ids: List[int] = []
    ) -> None:
        super().__init__(id, name, risk_text, stride, cwe_ids)

    @abstractmethod
    def apply(self, model: "Model") -> Optional["Risk"]:
        pass

    @abstractmethod
    def get_user_story_templates(self, repository: "UserStoryTemplateRepository") -> List["UserStoryTemplate"]:
        pass


class ComponentThreat(BaseThreat):
    def __init__(
        self, id: str, name: str, risk_text: str, stride: Stride, cwe_ids: List[int] = []
    ) -> None:
        super().__init__(id, name, risk_text, stride, cwe_ids)

    def is_applicable(self, component: "TechnicalComponent") -> bool:
        if component.out_of_scope:
            return False
        return True

    @abstractmethod
    def apply(self, component: "TechnicalComponent", model: "Model") -> Optional["Risk"]:
        pass

    def get_user_story_templates(self, repository: "UserStoryTemplateRepository", component: "TechnicalComponent") -> List["UserStoryTemplate"]:
        return repository.get_by_cwe(*self.cwe_ids)





