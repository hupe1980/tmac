from abc import ABC, abstractmethod
from collections.abc import MutableMapping
from typing import Dict, List, Tuple, Any, Optional, Iterator, TYPE_CHECKING
from enum import Enum

if TYPE_CHECKING:
    from .risk import Risk
    from .element import Element

class AttackCategory(Enum):
    ENGAGE_IN_DECEPTIVE_INTERACTIONS = "Engage in Deceptive Interactions"
    """Attack patterns within this category focus on malicious interactions with a
    target in an attempt to deceive the target and convince the target that it is 
    interacting with some other principal and as such take actions based on the 
    level of trust that exists between the target and the other principal.
    https://capec.mitre.org/data/definitions/156.html"""

    ABUSE_EXISTING_FUNCTIONALITY = "Abuse Existing Functionality"
    """An adversary uses or manipulates one or more functions of an application in 
    order to achieve a malicious objective not originally intended by the application, 
    or to deplete a resource to the point that the target's functionality is affected.
    https://capec.mitre.org/data/definitions/210.html"""

    MANIPULATE_DATA_STRUCTURES = "Manipulate Data Structures"
    """Attack patterns in this category manipulate and exploit characteristics of system 
    data structures in order to violate the intended usage and protections of these structures.
    https://capec.mitre.org/data/definitions/255.html"""

    MANIPULATE_SYSTEM_RESOURCES = "Manipulate System Resources"
    """Attack patterns within this category focus on the adversary's ability to manipulate one or 
    more resources in order to achieve a desired outcome.
    https://capec.mitre.org/data/definitions/262.html"""

    INJECT_UNEXPECTED_ITEMS = "Inject Unexpected Items"
    """Attack patterns within this category focus on the ability to control or disrupt the 
    behavior of a target either through crafted data submitted via an interface for data input, 
    or the installation and execution of malicious code on the target system.
    https://capec.mitre.org/data/definitions/152.html"""

    EMPLOY_PROBALILISTIC_TECHNIQUES = "Employ Probabilistic Techniques"
    """An attacker utilizes probabilistic techniques to explore and overcome security properties 
    of the target that are based on an assumption of strength due to the extremely low mathematical 
    probability that an attacker would be able to identify and exploit the very rare specific 
    conditions under which those security properties do not hold.
    https://capec.mitre.org/data/definitions/223.html"""

    MANIPULATE_TIMING_AND_STATE = "Manipulate Timing and State"
    """An attacker exploits weaknesses in timing or state maintaining functions to perform actions 
    that would otherwise be prevented by the execution flow of the target code and processes.
    https://capec.mitre.org/data/definitions/172.html"""

    COLLECT_AND_ANALYZE_INFORMATION = "Collect and Analyze Information"
    """Attack patterns within this category focus on the gathering, collection, and theft of 
    information by an adversary.
    https://capec.mitre.org/data/definitions/118.html
    """

    SUBVERT_ACCESS_CONTROL = "Subvert Access Control"
    """An attacker actively targets exploitation of weaknesses, limitations and assumptions 
    in the mechanisms a target utilizes to manage identity and authentication as well as 
    manage access to its resources or authorize functionality.
    https://capec.mitre.org/data/definitions/225.html
    """

    def __str__(self) -> str:
        return str(self.value)


class Threat(ABC):
    """Represents a possible threat"""

    def __init__(self, id: str, name: str, target: Tuple[Any, ...], category: AttackCategory, description: str = "", prerequisites: List[str] = [], mitigations: List[str] = [], cwe_ids: List[int] = []) -> None:
        self.id = id
        self.name = name
        self.target = target
        self.category = category
        self.description = description
        self.prerequisites = prerequisites
        self.mitigations = mitigations
        self.cwe_ids = cwe_ids

    def is_applicable(self, target: "Element") -> bool:
        if not isinstance(target, self.target) or target.in_scope is False:
            return False
        return True

    @abstractmethod
    def apply(self, target: "Element") -> Optional["Risk"]:
        pass

    def __str__(self) -> str:
        prerequisites = "\n".join(["- " + p for p in self.prerequisites])
        mitigations = "\n".join(["- " + m for m in self.mitigations])
        
        return f"""{self.id}: {self.name}

Description:
{self.description}

Prerequisites:
{prerequisites}

Mitigations:
{mitigations}
"""

class Threatlib(MutableMapping[str, Threat]):
    """Represents a threat library"""

    def __init__(self) -> None:
        self.excludes: List[str] = list() # TODO
        self._lib: Dict[str, "Threat"] = dict()

    def add_threats(self, *threats: "Threat") -> None:
        for threat in threats:
            self._lib[threat.id] = threat

    def apply(self, target: "Element") -> List["Risk"]:
        risks: List["Risk"] = list()

        for item in self.values():
            if item.id in self.excludes:
                continue

            if item.is_applicable(target):
                risk = item.apply(target)
                if risk is not None:
                    risks.append(risk)

        return risks

    def __getitem__(self, id: str) -> Threat:
        return self._lib[id]

    def __setitem__(self, id: str, value: Threat) -> None:
        self._lib[id] = value

    def __delitem__(self, id: str) -> None:
        del self._lib[id]

    def __iter__(self) -> Iterator[str]:
        return iter(self._lib)
    
    def __len__(self) -> int:
        return len(self._lib)
