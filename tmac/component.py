from abc import ABCMeta, abstractproperty
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, cast

from .data_flow import DataFlow, Protocol
from .diagram import DiagramNode
from .element import Element
from .node import Construct
from .otm import OpenThreatModelComponent
from .tag import TagMixin

if TYPE_CHECKING:
    from .asset import Asset
    from .risk import Risk
    from .trust_boundary import TrustBoundary


class MachineMeta(type):
    def __init__(cls, *args: Any) -> None:
        cls.UNKNOWN: "Machine" = cls("unknown")
        cls.PHYSICAL: "Machine" = cls("physical")
        cls.VIRTUAL: "Machine" = cls("virtual")
        cls.CONTAINER: "Machine" = cls("container")
        cls.SERVERLESS: "Machine" = cls("serverless")


class Machine(str, metaclass=MachineMeta):  # type: ignore[misc] # https://github.com/python/mypy/issues/14033
    def __new__(cls, value: str) -> "Machine":
        return super().__new__(cls, value)


class Technology(Enum):
    UNKNOWN = "unknown"
    # client_side
    CLI = "cli"
    BROWSER = "browser"
    DESKTOP = "desktop"
    MOBILE_APP = "mobile-app"
    WEB_UI = "web-ui"
    # server_side
    WEB_APPLICATION = "web-application"
    WEB_SERVICE_REST = "web-service-rest"
    WEB_SERVICE_SOAP = "web-service-soap"
    WEB_SERVICE_GRAPHQL = "web-service-graphql"
    LOAD_BALANCER = "load-balancer"
    # data_store
    DATABASE = "database"
    FILE_SERVER = "file-server"
    LOCAL_FILE_SYSTEM = "local-file-system"

    def __str__(self) -> str:
        return str(self.value)


class Encryption(Enum):
    NONE = "none"
    TRANSPARENT = "transparent"
    SYMMETRIC_SHARED_KEY = "symmetric-shared-key"
    ASYMMETRIC_SHARED_KEY = "asymmetric-shared-key"
    ENDUSER_INDIVIDUAL_KEY = "enduser-individual-key"

    def __str__(self) -> str:
        return str(self.value)


class DataFormat(Enum):
    JSON = "json"
    XML = "xml"
    SERIALIZATION = "serialization"
    FILE = "file"
    CSV = "csv"

    def __str__(self) -> str:
        return str(self.value)

class Component(Element, TagMixin, metaclass=ABCMeta):
    def __init__(self, scope: Construct, name: str, description: str = ""):
        super().__init__(scope, name, description)

        self._assets_processed: Set["Asset"] = set()
        self._assets_stored: Set["Asset"] = set()
    
    @abstractproperty
    def diagram_node(self) -> "DiagramNode":
        pass

    @abstractproperty
    def otm(self) -> "OpenThreatModelComponent":
        pass

    @property
    def incoming_flows(self) -> List["DataFlow"]:
        flows: Set["DataFlow"] = set()
        for flow in self._model.data_flows:
            if flow.destination == self:
                flows.add(flow)

        return list(flows)

    @property
    def outgoing_flows(self) -> List["DataFlow"]:
        flows: Set["DataFlow"] = set()
        for flow in self._model.data_flows:
            if flow.source == self:
                flows.add(flow)

        return list(flows)

    def add_data_flow(
        self,
        name: str,
        *,
        destination: "Component",
        protocol: "Protocol",
        **kwargs: Any,
    ) -> "DataFlow":
        return DataFlow(
            self,
            name,
            source=self,
            destination=destination,
            protocol=protocol,
            **kwargs,
        )

    def processes(self, *assets: "Asset") -> None:
        for asset in assets:
            self._assets_processed.add(asset)
            if isinstance(self, DataStore):
                self._assets_stored.add(asset)

    def stores(self, *assets: "Asset", skip_process: bool = False) -> None:
        for asset in assets:
            self._assets_stored.add(asset)
            if not skip_process:
                self._assets_processed.add(asset)

class Actor(Component):
    def __init__(
        self, 
        scope: Construct, 
        name: str,
        *,
        is_human: bool = False,
        description: str = "",
        overwrite_node_attrs: Dict[str, str] = dict(),
    ):
        super().__init__(scope, name, description)

        self.is_human = is_human
        self._overwrite_node_attrs = overwrite_node_attrs
    
    @property
    def diagram_node(self) -> "DiagramNode":
        return DiagramNode.from_attr(
            self.id,
            self.name,
            shape="box",
            labeljust="c",
            labelloc="c",
            **self._overwrite_node_attrs,
        )

    @property
    def otm(self) -> "OpenThreatModelComponent":
        return OpenThreatModelComponent(
            self.id,
            self.name,
            type="actor",
            description=self.description,
            tags=self.tags,
            attributes={
                "is_human": str(self.is_human),
            },
        )


class TechnicalComponent(Component):
    def __init__(
        self,
        scope: Construct,
        name: str,
        *,
        technology: Technology,
        machine: Machine = Machine.UNKNOWN,
        description: str = "",
        vendor: str = "",
        trust_boundary: Optional["TrustBoundary"] = None,
        human_use: bool = False,
        encryption: Encryption = Encryption.NONE,
        multi_tenant: bool = False,
        redundant: bool = False,
        custom_developed_parts: bool = False,
        accept_data_formats: List[DataFormat] = [],
        out_of_scope: bool = False,
        overwrite_node_attrs: Dict[str, str] = dict(),
    ):
        super().__init__(scope, name, description=description)

        self.trust_boundary = trust_boundary
        self.machine = machine
        self.technology = technology
        self.vendor = vendor
        self.human_use = human_use
        self.encryption = encryption
        self.multi_tenant = multi_tenant
        self.redundant = redundant
        self.custom_developed_parts = custom_developed_parts
        self.accept_data_formats = set(accept_data_formats)
        self.out_of_scope = out_of_scope

        self._overwrite_node_attrs = overwrite_node_attrs

    @abstractproperty
    def diagram_node(self) -> "DiagramNode":
        pass

    @property
    def otm(self) -> "OpenThreatModelComponent":
        return OpenThreatModelComponent(
            self.id,
            self.name,
            type=str(self.technology),
            description=self.description,
            tags=self.tags,
            attributes={
                "technologie": str(self.technology),
                "machine": str(self.machine),
                "encryption": str(self.encryption),
            },
        )

    @property
    def risks(self) -> List["Risk"]:
        return self._model.threat_library.apply(self._model, self)

    @property
    def max_average_asset_score(self) -> float:
        assets: Set["Asset"] = set.union(self._assets_processed, self._assets_stored)
        return cast(float, max([a.average_score for a in assets], default=0))

    @property
    def is_web_application(self) -> bool:
        return self.technology in [
            Technology.WEB_APPLICATION,
        ]

    @property
    def is_web_service(self) -> bool:
        return self.technology in [
            Technology.WEB_SERVICE_REST,
            Technology.WEB_SERVICE_SOAP,
            Technology.WEB_SERVICE_GRAPHQL,
        ]


class ExternalEntity(TechnicalComponent):
    """Task, entity, or data store outside of your direct control."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, out_of_scope=True, **kwargs)

    @property
    def diagram_node(self) -> "DiagramNode":
        return DiagramNode.from_attr(
            self.id,
            self.name,
            shape="box",
            labeljust="c",
            labelloc="c",
            **self._overwrite_node_attrs,
        )


class Process(TechnicalComponent):
    """Task that receives, modifies, or redirects input to output."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, **kwargs)

    @property
    def diagram_node(self) -> "DiagramNode":
        return DiagramNode.from_attr(
            self.id,
            self.name,
            shape="circle",
            labeljust="c",
            labelloc="c",
            **self._overwrite_node_attrs,
        )


class DataStore(TechnicalComponent):
    """Permanent and temporary data storage."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, **kwargs)

    @property
    def diagram_node(self) -> "DiagramNode":
        return DiagramNode.from_attr(
            self.id,
            self.name,
            shape="cylinder",
            labeljust="c",
            labelloc="c",
            **self._overwrite_node_attrs,
        )
