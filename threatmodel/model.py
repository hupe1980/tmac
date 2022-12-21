from abc import ABCMeta
from typing import Dict, List, Any, Optional, Set, TYPE_CHECKING
from enum import Enum
import uuid
from tabulate import tabulate

from .node import Construct
from .risk import Risk, Treatment
from .diagram import SequenceDiagram
from .table_format import TableFormat

if TYPE_CHECKING:
    from .control import Control
    from .data_flow import Data
    from .threat import Threatlib
    from .trust_boundary import TrustBoundary


class Model(Construct):
    @staticmethod
    def of(construct: "Construct") -> "Model":
        def lookup(c: "Construct") -> "Model":
            if isinstance(c, Model):
                return c

            if c.node.scope is None:
                raise ValueError(
                    "No model could be identified for the construct at path"
                )

            return lookup(c.node.scope)

        return lookup(construct)

    def __init__(self, title: str, threatlib: Optional["Threatlib"] = None) -> None:
        super().__init__(None, "")

        self.title = title

        if threatlib is None:
            # import when need to avoid circular import
            from .threatlib import DEFAULT_THREATLIB
            self.threatlib = DEFAULT_THREATLIB
        else:
            self.threatlib = threatlib

    @property
    def technical_assets(self):
        return list(filter(lambda c: isinstance(c, TechnicalAsset), self.node.find_all()))

    def evaluate(self) -> "Result":
        result = Result(self.title)

        for c in self.node.find_all():
            if isinstance(c, Element):
                result.add_risk(*c.risks)
                result.add_elements(c)

        return result


class Element(Construct):
    """A generic element"""

    def __init__(self, model: Construct, name: str, in_scope: bool = True, trust_boundary: Optional["TrustBoundary"] = None):
        super().__init__(model, name)

        self.name = name
        self.uniq_name = self._uniq_name()
        self.in_scope = in_scope
        self.trust_boundary = trust_boundary

        self._controls: Set["Control"] = set()

    @property
    def risks(self) -> List["Risk"]:
        threatlib = Model.of(self).threatlib
        return threatlib.apply(self)

    @property
    def controls(self) -> Set["Control"]:
        return self._controls

    def add_controls(self, *controls: "Control") -> None:
        for control in controls:
            self._controls.add(control)

    def remove_controls(self, *controls: "Control") -> None:
        for control in controls:
            self._controls.remove(control)

    def has_control(self, control: "Control") -> bool:
        return control in self._controls

    def get_risk_by_id(self, id: str) -> Risk:
        return [risk for risk in self.risks if risk.id == id][0]

    def risks_table(self, table_format: TableFormat = TableFormat.SIMPLE) -> str:
        headers = ["SID", "Severity", "Category", "Name", "Treatment"]
        table = []

        for risk in self.risks:
            table.append([risk.id, risk.severity, risk.category,
                         risk.name, risk.treatment])

        return tabulate(table, headers=headers, tablefmt=str(table_format))

    def _uniq_name(self) -> str:
        uid = str(uuid.uuid4())[:8]
        return f"{self.name}_{uid}"


class Result:
    def __init__(self, model_title: str) -> None:
        self.model_title = model_title
        self._risks: Dict[str, Risk] = dict()
        self._elements: List[Element] = list()

    def add_risk(self, *risks: Risk) -> None:
        for risk in risks:
            self._risks[risk.id] = risk

    def add_elements(self, *elements: Element) -> None:
        for element in elements:
            self._elements.append(element)

    def risks(self) -> List[Risk]:
        return list(self._risks.values())

    def get_risk_by_id(self, id: str) -> Risk:
        return self._risks[id]

    def treat_risk(self, id: str, treatment: Treatment) -> None:
        self._risks[id].treat(treatment)

    def risks_table(self, table_format: TableFormat = TableFormat.SIMPLE) -> str:
        headers = ["SID", "Severity", "Category",
                   "Name", "Affected", "Treatment"]
        table = []

        for risk in self._risks.values():
            table.append([risk.id, risk.severity, risk.category, risk.name,
                         risk.target, risk.treatment])

        return tabulate(table, headers=headers, tablefmt=str(table_format))

    def sequence_diagram(self) -> str:
        # import when need to avoid circular import
        from .data_flow import DataFlow

        diagram = SequenceDiagram(self.model_title)

        for e in self._elements:
            if isinstance(e, DataFlow):
                for data in e.data_sent:
                    diagram.add_message(e.source.uniq_name,
                                        e.sink.uniq_name, data.name)
                for data in e.data_received:
                    diagram.add_message(
                        e.sink.uniq_name, e.source.uniq_name, data.name)
                continue

            if isinstance(e, ExternalEntity):
                diagram.add_actor(e.uniq_name, e.name)
                continue

            if isinstance(e, DataStore):
                diagram.add_database(e.uniq_name, e.name)
                continue

            if isinstance(e, TechnicalAsset):
                diagram.add_entity(e.uniq_name, e.name)
                continue

        return diagram.render()



class TechnicalAssetType(Enum):
    EXTERNAL_ENTITY = "external-entity"
    PROCESS = "process"
    DATASTORE = "datastore"

    def __str__(self) -> str:
        return str(self.value)


class Machine(Enum):
    PHYSICAL = "physical"
    VIRTUAL = "virtual"
    CONTAINER = "container"
    SERVERLESS = "serverless"

    def __str__(self) -> str:
        return str(self.value)


class Technology(Enum):
    UNKNOWN = "unknown-technology"
    CLIENT_SYSTEM = "client-system"
    BROWSER = "browser"
    DESKTOP = "desktop"
    MOBILE_APP = "mobile-app"
    DEVOPS_CLIENT = "devops-client"
    WEB_SERVER = "web-server"
    WEB_APPLICATION = "web-application"
    APPLICATION_SERVER = "application-server"
    DATABASE = "database"
    FILE_SERVER = "file-server"
    LOCAL_FILE_SYSTEM = "local-file-system"
    ERP = "erp"
    CMS = "cms"
    WEB_SERVICE_REST = "web-service-rest"
    WEB_SERVICE_SOAP = "web-service-soap"
    EJB = "ejb"
    SEARCH_INDEX = "search-index"
    SEARCH_ENGINE = "search-engine"
    SERVICE_REGISTRY = "service-registry"
    REVERSE_PROXY = "reverse-proxy"
    LOAD_BALANCER = "load-balancer"
    BUILD_PIPELINE = "build-pipeline"
    SOURCECODE_REPOSITORY = "sourcecode-repository"
    ARTIFACT_REGISTRY = "artifact-registry"
    CODE_INSPECTION_PLATFORM = "code-inspection-platform"
    MONITORING = "monitoring"
    LDAP_SERVER = "ldap-server"
    CONTAINER_PLATFORM = "container-platform"
    BATCH_PROCESSING = "batch-processing"
    EVENT_LISTENER = "event-listener"
    IDENTITIY_PROVIDER = "identity-provider"
    IDENTITY_STORE_LDAP = "identity-store-ldap"
    IDENTITY_STORE_DATABASE = "identity-store-database"
    TOOL = "tool"
    CLI = "cli"
    TASK = "task"
    FUNCTION = "function"
    GATEWAY = "gateway"
    IOT_DEVICE = "iot-device"
    MESSAGE_QUEUE = "message-queue"
    STREAM_PROCESSING = "stream-processing"
    SERVICE_MESH = "service-mesh"
    DATA_LAKE = "data-lake"
    REPORT_ENGINE = "report-engine"
    AI = "ai"
    MAIL_SERVER = "mail-server"
    VAULT = "vault"
    HASM = "hsm"
    WAF = "waf"
    IDS = "ids"
    IPS = "ips"
    SCHEDULER = "scheduler"
    MAINFRAME = "mainframe"
    BLOCK_STORAGE = "block-storage"
    LIBRARY = "library"

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


class TechnicalAsset(Element, metaclass=ABCMeta):
    def __init__(self, scope: Construct, name: str,
                 type: TechnicalAssetType,
                 machine: Machine,
                 technology: Technology,
                 environment_variables: bool = False,
                 human_use: bool = False,
                 internet_facing: bool = False,
                 encryption: Encryption = Encryption.NONE,
                 multi_tenant: bool = False,
                 redundant: bool = False,
                 custom_developed_parts: bool = False,
                 accept_data_formats: List[DataFormat] = [],
                 ):
        super().__init__(scope, name)

        self.type = type
        self.machine = machine
        self.technology = technology
        self.environment_variables = environment_variables
        self.human_use = human_use
        self.internet_facing = internet_facing
        self.encryption = encryption
        self.multi_tenant = multi_tenant
        self.redundant = redundant
        self.custom_developed_parts = custom_developed_parts
        self.accept_data_formats = accept_data_formats

        self._data_assets_processed: Set["Data"] = set()
        self._data_assets_stored: Set["Data"] = set()

    def processes(self, *data: "Data") -> None:
        for item in data:
            self._data_assets_processed.add(item)

    def stores(self, *data: "Data", no_process: bool = False) -> None:
        for item in data:
            self._data_assets_stored.add(item)
            if not no_process:
                self._data_assets_processed.add(item)

    def is_web_application(self) -> bool:
        return self.technology in [
            Technology.WEB_SERVER,
            Technology.WEB_APPLICATION,
            Technology.APPLICATION_SERVER,
            Technology.ERP,
            Technology.CMS,
            Technology.IDENTITIY_PROVIDER,
            Technology.REPORT_ENGINE,
        ]

    def is_web_service(self) -> bool:
        return self.technology in [
            Technology.WEB_SERVICE_REST,
            Technology.WEB_SERVICE_SOAP,
        ]


class ExternalEntity(TechnicalAsset):
    """Task, entity, or data store outside of your direct control."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, TechnicalAssetType.EXTERNAL_ENTITY, **kwargs)


class Process(TechnicalAsset):
    """Task that receives, modifies, or redirects input to output."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, TechnicalAssetType.PROCESS, **kwargs)


class DataStore(TechnicalAsset):
    """Permanent and temporary data storage."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, TechnicalAssetType.DATASTORE, **kwargs)
