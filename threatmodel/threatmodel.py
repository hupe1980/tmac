from abc import ABC, ABCMeta, abstractmethod
from typing import Dict, List, Tuple, Any, Optional, Set
from enum import Enum
import uuid

from .node import Construct


class Model(Construct):
    @staticmethod
    def of(construct: "Construct") -> "Model":
        def lookup(c: "Construct") -> "Model":
            if isinstance(c, Model):
                return c

            if c.node.scope is None:
                raise ValueError(
                    "No model could be identified for the construct at path")

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
        result = Result()

        for c in self.node.find_all():
            if isinstance(c, Element):
                result.add_risk(*c.risks)

        return result


class Element(Construct):
    """A generic element"""

    def __init__(self, model: Construct, name: str):
        super().__init__(model, name)
        self.name = name
        self.uuid = uuid.uuid4()
        self.controls = Controls()

    @property
    def risks(self) -> List["Risk"]:
        threatlib = Model.of(self).threatlib
        return threatlib.apply(self)


class Risk:
    def __init__(self, element: Element, threat: "Threat") -> None:
        self.target = element.name
        self.description = threat.description
        self.details = threat.details
        self.severity = threat.severity
        self.likelihood = threat.likelihood

    def __str__(self) -> str:
        return f"'{self.target}': {self.description}\n{self.details}\n{self.severity}"


class Result:
    def __init__(self) -> None:
        self.risks: List[Risk] = list()

    def add_risk(self, *risks: Risk) -> None:
        for risk in risks:
            self.risks.append(risk)


class Data:
    """Represents a single piece of data that traverses the system"""

    def __init__(self, name):
        pass


class Controls:
    """Controls implemented by/on and Element"""

    checksInputBounds = False
    sanitizesInput = False


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


class DataFlow(Element):
    """A data flow from a source to a sink"""

    def __init__(self, model, name, source, sink, protocol):
        super().__init__(model, name)

        self.source = source
        self.sink = sink
        self.protocol = protocol

        self._data_sent: Set["Data"] = set()
        self._data_received: Set["Data"] = set()

    def sends(self, *data: Data) -> None:
        for item in data:
            self._data_sent.add(item)

    def receives(self, *data: Data) -> None:
        for item in data:
            self._data_received.add(item)

    @property
    def encrypted(self) -> bool:
        if self.protocol in [
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
        ]:
            return True
        return False

    @property
    def bidirectional(self) -> bool:
        return len(self._data_sent) > 0 and len(self._data_received) > 0


class TechnicalAssetType(Enum):
    EXTERNAL_ENTITY = "external-entity"
    PROCESS = "process"
    DATASTORE = "datastore"


class Machine(Enum):
    PHYSICAL = "physical"
    VIRTUAL = "virtual"
    CONTAINER = "container"
    SERVERLESS = "serverless"


class TechnicalAsset(Element, metaclass=ABCMeta):
    def __init__(self, scope: Construct, name: str, type: TechnicalAssetType, machine: Machine, environment_variables: bool = False, internet: bool = False):
        super().__init__(scope, name)

        self.machine = machine
        self.environment_variables = environment_variables
        self.internet = internet

        self._data_assets_processed: Set[Data] = set()
        self._data_assets_stored: Set[Data] = set()

    def processes(self, *data: Data) -> None:
        for item in data:
            self._data_assets_processed.add(item)

    def stores(self, *data: Data) -> None:
        for item in data:
            self._data_assets_stored.add(item)


class ExternalEntity(TechnicalAsset):
    """A External entity represent any entity outside of the application that sends or
receives data, communicating with the system."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, TechnicalAssetType.EXTERNAL_ENTITY, **kwargs)


class Process(TechnicalAsset):
    """A Process represents a task that handles data within the application."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, TechnicalAssetType.PROCESS, **kwargs)


class DataStore(TechnicalAsset):
    """A DataStore represents locations where the data are stored."""

    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, TechnicalAssetType.DATASTORE, **kwargs)


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


class Likelihood(Enum):
    UNLIKELY = "unlikely",
    LIKELY = "likely",
    VERY_LIKELY = "very-likely",
    FREQUENT = "frequent",


class Threat(ABC):
    """Represents a possible threat"""

    def __init__(self, id: str, target: Tuple[Any, ...], description: str = "", details: str = "", severity: Severity = Severity.HIGH, likelihood: Likelihood = Likelihood.VERY_LIKELY, condition: str = "", prerequisites: str = "", mitigations: str = "", example: str = "", references: str = "") -> None:
        self.id = id
        self.description = description
        self.target = target
        self.details = details
        self.severity = severity
        self.likelihood = likelihood
        self.condition = condition

    def is_applicable(self, target: "Element") -> bool:
        if not isinstance(target, self.target):
            return False
        return True

    @abstractmethod
    def apply(self, target: "Element") -> Optional["Risk"]:
        pass


class Threatlib:
    """Represents a threat library"""

    def __init__(self) -> None:
        self.lib: Dict[str, "Threat"] = dict()

    def add_threats(self, *threats: "Threat") -> None:
        for threat in threats:
            self.lib[threat.id] = threat

    def apply(self, target: "Element") -> List["Risk"]:
        risks: List["Risk"] = list()

        for item in self.lib.values():
            if item.is_applicable(target):
                risk = item.apply(target)
                if risk is not None:
                    risks.append(risk)

        return risks
