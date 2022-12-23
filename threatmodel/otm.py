import json
from abc import ABC
from typing import List, Dict


class OpenThreatModelEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, set):
            return list(o)
        return o.__dict__


class BaseOpenThreatModel(ABC):
    def to_json(self, indent: int = 4) -> str:
        return json.dumps(self, indent=indent, cls=OpenThreatModelEncoder)

    def __str__(self) -> str:
        return self.to_json(indent=4)

class OpenThreatModelProject(BaseOpenThreatModel):
    def __init__(self, name: str, id: str, description: str = "", owner: str = "", owner_contact: str = "", tags: List[str] = list(), attributes: Dict[str, str] = dict()):
        self.name = name
        self.id = id
        self.description = description
        self.owner = owner
        self.ownerContact = owner_contact
        self.tags = set(tags)
        self.attributes = attributes


class OpenThreatModelAsset(BaseOpenThreatModel):
    def __init__(self, id: str, name: str,
                 description: str = "",
                 attributes: Dict[str, str] = dict(),
                 ):
        self.id = id
        self.name = name
        self.description = description
        self.attributes = attributes

class OpenThreatModelComponent(BaseOpenThreatModel):
    def __init__(self, id: str, name: str, type: str,
                 tags: List[str] = list(),
                 description: str = "",
                 attributes: Dict[str, str] = dict(),
                 ):
        self.id = id
        self.name = name
        self.type = type
        self.tags = set(tags)
        self.description = description
        self.attributes = attributes

class OpenThreatModelThreatInstance(BaseOpenThreatModel):
    def __init__(self, threat: str, state: str) -> None:
        self.threat = threat
        self.state = state

    def __eq__(self, other):
        return self.threat == other.threat

    def __hash__(self):
        return id(self.threat)


class OpenThreatModelDataFlow(BaseOpenThreatModel):
    def __init__(self, id: str, name: str, source: str, destination: str,
                 description: str = "",
                 tags: List[str] = list(),
                 bidirectional: bool = False,
                 assets: List[str] = list(),
                 threats: List["OpenThreatModelThreatInstance"] = list(),
                 attributes: Dict[str, str] = dict(),
                 ) -> None:
        self.id = id
        self.name = name
        self.description = description
        self.tags = tags
        self.bidirectional = bidirectional
        self.source = source
        self.destination = destination
        self.assets = set(assets)
        self.threats = set(threats)
        self.attributes = attributes


class OpenThreatModelThreat(BaseOpenThreatModel):
     def __init__(self, id: str, name: str,
                 description: str = "",
                 categories: List[str] = list(),
                 cwes: List[str] = list(),
                 attributes: Dict[str, str] = dict(),
                 ):
        self.id = id
        self.name = name
        self.description = description
        self.categories = set(categories)
        self.cwes = set(cwes)
        self.attributes = attributes


class OpenThreatModelMitigation(BaseOpenThreatModel):
     def __init__(self, id: str, name: str,
                 description: str = "",
                 risk_reduction: int = 0,
                 attributes: Dict[str, str] = dict(),
                 ):
        self.id = id
        self.name = name
        self.description = description
        self.riskReduction = risk_reduction
        self.attributes = attributes


class OpenThreatModel(BaseOpenThreatModel):
    def __init__(self, project: "OpenThreatModelProject",
                 assets: List["OpenThreatModelAsset"] = list(),
                 components: List["OpenThreatModelComponent"] = list(),
                 data_flows: List["OpenThreatModelDataFlow"] = list(),
                 ):
        self.otmVersion = "0.1.0"
        self.project = project
        self.assets = set(assets)
        self.components = set(components)
        self.dataflows = set(data_flows)
