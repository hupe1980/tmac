from typing import Set, Dict, TYPE_CHECKING
from enum import Enum

from .common import OrderedEnum
from .diagram import DataFlowDiagram
from .node import Construct
from .element import Element

if TYPE_CHECKING:
    from .asset import TechnicalAsset


class Classification(OrderedEnum):
    UNKNOWN = 0
    
    PUBLIC = 1
    """This type of data is freely accessible to the public (i.e. all employees/company personnel). 
    It can be freely used, reused, and redistributed without repercussions. An example might be 
    first and last names, job descriptions, or press releases"""

    INTERNAL_ONLY = 2
    """This type of data is strictly accessible to internal company personnel or internal employees 
    who are granted access. This might include internal-only memos or other communications, business 
    plans, etc."""

    CONFIDENTIAL = 3
    """Access to confidential data requires specific authorization and/or clearance. Types of confidential 
    data might include Social Security numbers, cardholder data, M&A documents, and more. Usually, confidential 
    data is protected by laws like HIPAA and the PCI DSS."""

    RESTRICTED = 4
    """Restricted data includes data that, if compromised or accessed without authorization, which could lead 
    to criminal charges and massive legal fines or cause irreparable damage to the company. Examples of restricted 
    data might include proprietary information or research and data protected by state and federal regulations."""


    def __str__(self) -> str:
        value_map = {
            "0": "Unknown class",
            "1": "Public",
            "2": "Internal-only",
            "3": "Confidential",
            "4": "Restricted"
        }

        return value_map[str(self.value)]
    

class Data:
    """Represents a single piece of data that traverses the system"""

    def __init__(self, name: str, classification: Classification = Classification.UNKNOWN, pii: bool = False):
        self.name = name
        self.classificatio = classification
        self.pii = pii


class Protocol(Enum):
    UNKNOEN = "unknown-protocol"
    HTTP = "http"
    HTTPS = "https"
    WS = "ws"
    WSS = "wss"
    MQTT = "mqtt"
    JDBC = "jdbc"
    JDBC_ENCRYPTED = "jdbc-encrypted"
    ODBC = "odbc"
    ODBC_ENCRYPTED = "odbc-encrypted"
    SQL = "sql"
    SQL_ENCRYPTED = "sql-encrypted"
    NOSQL = "nosql"
    NOSQL_ENCRYPTED = "nosql-encrypted"
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
                 readonly: bool = False,
                 authentication: Authentication = Authentication.NONE,
                 authorization: Authorization = Authorization.NONE,
                 overwrite_edge_attrs: Dict[str, str] = dict()
                 ):
        super().__init__(scope, name)

        self.source = source
        self.sink = sink
        self.protocol = protocol
        self.vpn = vpn
        self.readonly = readonly
        self.authentication = authentication
        self.authorization = authorization
        self.overwrite_edge_attrs = overwrite_edge_attrs

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
            Protocol.SQL,
            Protocol.JDBC_ENCRYPTED,
            Protocol.ODBC_ENCRYPTED,
            Protocol.SQL_ENCRYPTED,
        ]

    def is_nosql_database_protocol(self) -> bool:
        return self.protocol in [
            Protocol.NOSQL,
            Protocol.NOSQL_ENCRYPTED,
        ]

    def is_encrypted(self) -> bool:
        return self.vpn or self.protocol in [
            Protocol.HTTPS,
            Protocol.WSS,
            Protocol.JDBC_ENCRYPTED,
            Protocol.ODBC_ENCRYPTED,
            Protocol.NOSQL_ENCRYPTED,
            Protocol.SQL_ENCRYPTED,
            Protocol.BINARY_ENCRYPTED,
            Protocol.TEXT_ENCRYPTED,
            Protocol.SSH,
            Protocol.SSH_TUNNEL,
            Protocol.FTPS,
            Protocol.SCP,
            Protocol.LDAPS,
            Protocol.IIOP_ENCRYPTED,
            Protocol.JRMP_ENCRYPTED,
            Protocol.SMB_ENCRYPTED,
            Protocol.SMTP_ENCRYPTED,
            Protocol.POP3_ENCRYPTED,
            Protocol.IMAP_ENCRYPTED,
        ]

    def is_bidirectional(self) -> bool:
        return len(self._data_sent) > 0 and len(self._data_received) > 0

    def data_flow_diagram(self, auto_view = True):
        diagram = DataFlowDiagram(self.name)

        diagram.add_data_flow(self.source.uniq_name, self.sink.uniq_name, f"{self.protocol}: {self.name}", **self.overwrite_edge_attrs)
        diagram.add_asset(self.source.uniq_name, self.source.name, self.source.shape, **self.source.overwrite_node_attrs)
        diagram.add_asset(self.sink.uniq_name, self.sink.name, self.sink.shape, **self.sink.overwrite_node_attrs)

        if auto_view is False or self._model.is_ci():
            diagram.save()
            return

        if self._model.is_notebook():
            from IPython import display
            display.display(diagram)
        else:
            diagram.view()

