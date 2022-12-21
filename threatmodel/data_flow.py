from typing import Set, TYPE_CHECKING
from enum import Enum

from .node import Construct
from .element import Element

if TYPE_CHECKING:
    from .asset import TechnicalAsset


class Data:
    """Represents a single piece of data that traverses the system"""

    def __init__(self, name):
        self.name = name


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

