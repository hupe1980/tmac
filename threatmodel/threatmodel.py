from abc import ABC, ABCMeta, abstractmethod
from typing import Dict, List, Tuple, Any, Optional, Set
from enum import Enum
import uuid
from tabulate import tabulate

from .node import Construct
from .table_format import TableFormat


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


class Impact(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very-high"

    def __str__(self) -> str:
        return str(self.value)


class Likelihood(Enum):
    UNLIKELY = "unlikely"
    LIKELY = "likely"
    VERY_LIKELY = "very-likely"
    FREQUENT = "frequent"

    def __str__(self) -> str:
        return str(self.value)


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return str(self.value)


class Treatment(Enum):
    UNCHECKED = "unchecked"
    IN_DISCUSSION = "in-discussion"
    REDUCED = "reduced"
    TRANSFERRED = "transferred"
    AVOIDED = "avoided"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false-positive"

    def __str__(self) -> str:
        return str(self.value)


class Risk:
    def __init__(self, element: "Element", threat: "Threat", impact: "Impact", likelihood: "Likelihood", fix_severity: Optional["Severity"] = None) -> None:
        self.id = f"{threat.id}@{element.name}"
        self.target = element.name
        self.category = threat.category
        self.name = threat.name
        self.description = threat.description
        self.impact = impact
        self.likelihood = likelihood

        if fix_severity is None:
            self.severity = self._calculate_severity(impact, likelihood)
        else:
            self.severity = fix_severity

        self._treatment = Treatment.UNCHECKED

    @property
    def treatment(self) -> Treatment:
        return self._treatment

    def treat(self, treatment: Treatment) -> None:
        self._treatment = treatment

    def _calculate_severity(self, impact: "Impact", likelihood: "Likelihood") -> "Severity":
        impact_weights = {Impact.LOW: 1, Impact.MEDIUM: 2,
                          Impact.HIGH: 3, Impact.VERY_HIGH: 4}
        likelihood_weights = {Likelihood.UNLIKELY: 1, Likelihood.LIKELY: 2,
                              Likelihood.VERY_LIKELY: 3, Likelihood.FREQUENT: 4}

        result = likelihood_weights[likelihood] * impact_weights[impact]

        if result <= 1:
            return Severity.LOW

        if result <= 3:
            return Severity.MEDIUM

        if result <= 8:
            return Severity.ELEVATED

        if result <= 12:
            return Severity.HIGH

        return Severity.CRITICAL

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.id, hex(id(self))
        )

    def __str__(self) -> str:
        return f"'{self.target}': {self.name}\n{self.description}\n{self.severity}"


class Element(Construct):
    """A generic element"""

    def __init__(self, model: Construct, name: str, in_scope: bool = True, trust_boundary: Optional["TrustBoundary"] = None):
        super().__init__(model, name)

        self.name = name
        self.uniq_name = self._uniq_name()
        self.in_scope = in_scope
        self.trust_boundary = trust_boundary

        self._controls: Set["Controls"] = set()

    @property
    def risks(self) -> List["Risk"]:
        threatlib = Model.of(self).threatlib
        return threatlib.apply(self)

    @property
    def controls(self) -> Set["Controls"]:
        return self._controls

    def add_controls(self, *controls: "Controls") -> None:
        for control in controls:
            self._controls.add(control)

    def remove_controls(self, *controls: "Controls") -> None:
        for control in controls:
            self._controls.remove(control)

    def has_control(self, control: "Controls") -> bool:
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
        participants: List[str] = list()
        messages: List[str] = list()

        for e in self._elements:
            if isinstance(e, DataFlow):
                for data in e.data_sent:
                    messages.append(f"{e.source.uniq_name} -> {e.sink.uniq_name}: {data.name}")
                for data in e.data_received:
                    messages.append(f"{e.sink.uniq_name} -> {e.source.uniq_name}: {data.name}")
                continue

            if isinstance(e, ExternalEntity):
                participants.append(f'actor {e.uniq_name} as "{e.name}"')
                continue

            if isinstance(e, DataStore):
                participants.append(f'database {e.uniq_name} as "{e.name}"')
                continue

            if isinstance(e, TechnicalAsset):
                participants.append(f'entity {e.uniq_name} as "{e.name}"')
                continue

        template = """@startuml {title}
{participants}
{messages}
@enduml"""

        return template.format(title=self.model_title, participants="\n".join(participants), messages="\n".join(messages))


class TrustBoundary(Element):
    """Trust zone changes as data flows through the system."""

    def __init__(self, scope: Construct, name: str) -> None:
        super().__init__(scope, name)


class Data:
    """Represents a single piece of data that traverses the system"""

    def __init__(self, name):
        self.name = name


class Controls(Enum):
    """Controls implemented by/on and Element"""

    INPUT_BOUNDS_CHECKS = "input-bounds-checks"
    
    INPUT_SANITIZING = "input-sanitizing"
    
    INPUT_VALIDATION = "input-validation"
    
    Parameterization = "parameterization"
    """Parameterized queries or stored procedures"""
    
    SERVER_SIDE_INCLUDES_DEACTIVATION = "server-side-includes-deactivation"
    
    WAF = "waf"

    def __str__(self) -> str:
        return str(self.value)


class Protocol(Enum):
    UNKNOEN = "unknown-protocol"
    HTTP = "http"
    HTTPS = "https"
    WS = "ws"
    WSS = "wss"
    REVERSE_PROXY_WEB_PROTOCOL = "reverse-proxy-web-protocol"
    REVERSE_PROXY_WEB_PROTOCOL_ENCRYPTED = "reverse-proxy-web-protocol-encrypted"
    MQTT = "mqtt"
    JDBC = "jdbc"
    JDBC_ENCRYPTED = "jdbc-encrypted"
    ODBC = "odbc"
    ODBC_ENCRYPTED = "odbc-encrypted"
    SQL_ACCESS_PROTOCOL = "sql-access-protocol"
    SQL_ACCESS_PROTOCOL_ENCRYPTED = "sql-access-protocol-encrypted"
    NOSQL_ACCESS_PROTOCOL = "nosql-access-protocol"
    NOSQL_ACCESS_PROTOCOL_ENCRYPTED = "nosql-access-protocol-encrypted"
    BINARY = "binary"
    BINARY_ENCRYPTED = "binary-encrypted"
    TEXT = "text"
    TEXT_ENCRYPTED = "text-encrypted"
    SSH = "ssh"
    SSH_TUNNEL = "ssh-tunnel"
    SMTP = "smtp"
    SMTP_ENCRYPTED = "smtp-encrypted"
    POP3 = "pop3"
    POP3_ENCRYPTED = "pop3-encrypted"
    IMAP = "imap"
    IMAP_ENCRYPTED = "imap-encrypted"
    FTP = "ftp"
    FTPS = "ftps"
    SFTP = "sftp"
    SCP = "scp"
    LDAP = "ldap"
    LDAPS = "ldaps"
    JMS = "jms"
    NFS = "nfs"
    SMB = "smb"
    SMB_ENCRYPTED = "smb-encrypted"
    LOCAL_FILE_ACCESS = "local-file-access"
    NRPE = "nrpe"
    XMPP = "xmpp"
    IIOP = "iiop"
    IIOP_ENCRYPTED = "iiop-encrypted"
    JRMP = "jrmp"
    JRMP_ENCRYPTED = "jrmp-encrypted"
    IN_PROCESS_LIBRARY_CALL = "in-process-library-call"
    CONTAINER_SPAWNING = "container-spawning"

    def __str__(self) -> str:
        return str(self.value)


class Authentication(Enum):
    NONE = "none",
    CREDENTIALS = "credentials"
    SESSION_ID = "session-id"
    TOKEN = "token"
    CLIENT_CERTIFICATE = "client-certificate"
    TWO_FACTOR = "two-factor"
    EXTERNALIZED = "externalized"

    def __str__(self) -> str:
        return str(self.value)


class Authorization(Enum):
    NONE = "none"
    TECHNICAL_USER = "technical-user"
    ENDUSER_IDENTITY_PROPAGATION = "enduser-identity-propagation"

    def __str__(self) -> str:
        return str(self.value)


class DataFlow(Element):
    """Data movement between processes, data stores, and external entities"""

    def __init__(self, scope: Construct, name: str,
                 source: "TechnicalAsset",
                 sink: "TechnicalAsset",
                 protocol: Protocol,
                 vpn: bool = False,
                 authentication: Authentication = Authentication.NONE,
                 authorization: Authorization = Authorization.NONE,
                 ):
        super().__init__(scope, name)

        self.source = source
        self.sink = sink
        self.protocol = protocol
        self.vpn = vpn
        self.authentication = authentication
        self.authorization = authorization

        self._data_sent: Set["Data"] = set()
        self._data_received: Set["Data"] = set()

    def sends(self, *data: Data) -> None:
        for item in data:
            self._data_sent.add(item)
            self._update_partipants(item)

    def receives(self, *data: Data) -> None:
        for item in data:
            self._data_received.add(item)
            self._update_partipants(item)

    @property
    def data_sent(self) -> Set["Data"]:
        return self._data_sent

    @property
    def data_received(self) -> Set["Data"]:
        return self._data_received

    def _update_partipants(self, data: Data) -> None:
        self.source.processes(data)
        self.sink.processes(data)

    def is_relational_database_protocol(self) -> bool:
        return self.protocol in [
            Protocol.JDBC,
            Protocol.ODBC,
            Protocol.SQL_ACCESS_PROTOCOL,
            Protocol.JDBC_ENCRYPTED,
            Protocol.ODBC_ENCRYPTED,
            Protocol.SQL_ACCESS_PROTOCOL_ENCRYPTED,
        ]

    def is_nosql_database_protocol(self) -> bool:
        return self.protocol in [
            Protocol.NOSQL_ACCESS_PROTOCOL,
            Protocol.NOSQL_ACCESS_PROTOCOL_ENCRYPTED,
        ]

    def is_encrypted(self) -> bool:
        return self.vpn or self.protocol in [
            Protocol.HTTPS,
            Protocol.WSS,
            Protocol.JDBC_ENCRYPTED,
            Protocol.ODBC_ENCRYPTED,
            Protocol.NOSQL_ACCESS_PROTOCOL_ENCRYPTED,
            Protocol.SQL_ACCESS_PROTOCOL_ENCRYPTED,
            Protocol.BINARY_ENCRYPTED,
            Protocol.TEXT_ENCRYPTED,
            Protocol.SSH,
            Protocol.SSH_TUNNEL,
            Protocol.FTPS,
            Protocol.SCP,
            Protocol.LDAPS,
            Protocol.REVERSE_PROXY_WEB_PROTOCOL_ENCRYPTED,
            Protocol.IIOP_ENCRYPTED,
            Protocol.JRMP_ENCRYPTED,
            Protocol.SMB_ENCRYPTED,
            Protocol.SMTP_ENCRYPTED,
            Protocol.POP3_ENCRYPTED,
            Protocol.IMAP_ENCRYPTED,
        ]

    def is_bidirectional(self) -> bool:
        return len(self._data_sent) > 0 and len(self._data_received) > 0


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

        self._data_assets_processed: Set[Data] = set()
        self._data_assets_stored: Set[Data] = set()

    def processes(self, *data: Data) -> None:
        for item in data:
            self._data_assets_processed.add(item)

    def stores(self, *data: Data, no_process: bool = False) -> None:
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


class Threatlib:
    """Represents a threat library"""

    def __init__(self) -> None:
        self.lib: Dict[str, "Threat"] = dict()
        self.excludes: List[str] = list()

    def add_threats(self, *threats: "Threat") -> None:
        for threat in threats:
            self.lib[threat.id] = threat

    def apply(self, target: "Element") -> List["Risk"]:
        risks: List["Risk"] = list()

        for item in self.lib.values():
            if item.id in self.excludes:
                continue

            if item.is_applicable(target):
                risk = item.apply(target)
                if risk is not None:
                    risks.append(risk)

        return risks
