from abc import ABCMeta, abstractproperty
from typing import Any, Set, Optional, List, Dict, TYPE_CHECKING
from enum import Enum

from .node import Construct, TagMixin
from .element import Element
from .otm import OpenThreatModelComponent

if TYPE_CHECKING:
    from .asset import Asset
    from .trust_boundary import TrustBoundary


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
    HSM = "hsm"
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


class Component(Element, TagMixin, metaclass=ABCMeta):
    def __init__(self, scope: Construct, name: str,
                 machine: Machine,
                 technology: Technology,
                 description: str = "",
                 trust_boundary: Optional["TrustBoundary"] = None,
                 uses_environment_variables: bool = False,
                 human_use: bool = False,
                 internet_facing: bool = False,
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
        self.human_use = human_use
        self.internet_facing = internet_facing
        self.encryption = encryption
        self.multi_tenant = multi_tenant
        self.redundant = redundant
        self.custom_developed_parts = custom_developed_parts
        self.accept_data_formats = accept_data_formats
        self.overwrite_node_attrs = overwrite_node_attrs

        self._out_of_scope = out_of_scope
        self._uses_environment_variables = uses_environment_variables
        self._assets_processed: Set["Asset"] = set()
        self._assets_stored: Set["Asset"] = set()

    @property
    def out_of_scope(self) -> bool:
        return self._out_of_scope

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
            }
        )

    def processes(self, *assets: "Asset") -> None:
        for asset in assets:
            self._assets_processed.add(asset)

    def stores(self, *assets: "Asset", skip_process: bool = False) -> None:
        for asset in assets:
            self._assets_stored.add(asset)
            if not skip_process:
                self._assets_processed.add(asset)

    def is_using_environment_variables(self) -> bool:
        return self._uses_environment_variables

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

    @abstractproperty
    def shape(self) -> str:
        pass


class ExternalEntity(Component):
    """Task, entity, or data store outside of your direct control."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, out_of_scope=True, **kwargs)
    
    @property
    def shape(self) -> str:
        return "box"


class Process(Component):
    """Task that receives, modifies, or redirects input to output."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, **kwargs)

    @property
    def shape(self) -> str:
        return "circle"


class DataStore(Component):
    """Permanent and temporary data storage."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, **kwargs)

    @property
    def shape(self) -> str:
        return "cylinder"
