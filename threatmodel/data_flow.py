from typing import Set, Dict, List, Union, overload, TYPE_CHECKING, cast
from enum import Enum

from .asset import Asset
from .diagram import DataFlowDiagram
from .node import Construct, TagMixin
from .element import Element
from .otm import OpenThreatModelDataFlow, OpenThreatModelThreatInstance
from .score import Score

if TYPE_CHECKING:
    from .component import Component


# class Classification(OrderedEnum):
#     UNKNOWN = 0

#     PUBLIC = 1
#     """This type of data is freely accessible to the public (i.e. all employees/company personnel).
#     It can be freely used, reused, and redistributed without repercussions. An example might be
#     first and last names, job descriptions, or press releases"""

#     INTERNAL_ONLY = 2
#     """This type of data is strictly accessible to internal company personnel or internal employees
#     who are granted access. This might include internal-only memos or other communications, business
#     plans, etc."""

#     CONFIDENTIAL = 3
#     """Access to confidential data requires specific authorization and/or clearance. Types of confidential
#     data might include Social Security numbers, cardholder data, M&A documents, and more. Usually, confidential
#     data is protected by laws like HIPAA and the PCI DSS."""

#     RESTRICTED = 4
#     """Restricted data includes data that, if compromised or accessed without authorization, which could lead
#     to criminal charges and massive legal fines or cause irreparable damage to the company. Examples of restricted
#     data might include proprietary information or research and data protected by state and federal regulations."""

#     def __str__(self) -> str:
#         value_map = {
#             "0": "Unknown class",
#             "1": "Public",
#             "2": "Internal-only",
#             "3": "Confidential",
#             "4": "Restricted"
#         }

#         return value_map[str(self.value)]


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
    NONE = "none"
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


class DataFlow(Element, TagMixin):
    """Asset transfers between processes, data stores, and external entities"""

    def __init__(
        self, scope: Construct, name: str, *,
        source: "Component",
        destination: "Component",
        protocol: Protocol,
        description: str = "",
        vpn: bool = False,
        readonly: bool = False,
        bidirectional: bool = False,
        authentication: Authentication = Authentication.NONE,
        authorization: Authorization = Authorization.NONE,
        overwrite_edge_attrs: Dict[str, str] = dict()
    ):
        """
        Constructs all the necessary attributes for the data_flow object.

        Parameters
        ----------
            scope: The scope in which to define this construct.

        """
        super().__init__(scope, name, description=description)

        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.description = description
        self.vpn = vpn
        self.readonly = readonly
        self.bidirectional = bidirectional
        self.authentication = authentication
        self.authorization = authorization
        self.overwrite_edge_attrs = overwrite_edge_attrs

        self._assets: Set["Asset"] = set()

    @property
    def out_of_scope(self) -> bool:
        return self.source.out_of_scope and self.destination.out_of_scope

    @property
    def assets(self) -> Set["Asset"]:
        return self._assets

    @property
    def max_average_asset_score(self) -> float:
        return cast(float, max([a.average_asset_score for a in self.assets], default=0))

    @property
    def otm(self) -> "OpenThreatModelDataFlow":
        return OpenThreatModelDataFlow(
            self.id,
            self.name,
            self.source.id,
            self.destination.id,
            description=self.description,
            tags=self.tags,
            bidirectional=self.bidirectional,
            assets=[a.id for a in self._assets],
            threats=[OpenThreatModelThreatInstance(
                r.id, str(r.treatment)) for r in self.risks],
            attributes={
                "protocol": str(self.protocol),
                "vpn": str(self.vpn),
                "readonly": str(self.readonly),
                "authentication": str(self.authentication),
                "authorization": str(self.authorization),
            }
        )

    def validate(self) -> List[str]:
        if len(self.assets) == 0:
            return [f"Unnecessary Communication Link: {self.name}"]
        return []

    @overload
    def transfers(self, asset: "Asset") -> "Asset":
        ...

    @overload
    def transfers(self, asset: str, *, confidentiality: Score, integrity: Score, availability: Score) -> "Asset":
        ...

    def transfers(self, asset: Union["Asset", str], confidentiality: Score = Score.NONE, integrity: Score = Score.NONE, availability: Score = Score.NONE) -> "Asset":
        if isinstance(asset, Asset):
            self._assets.add(asset)
            self.source.processes(asset)
            self.destination.processes(asset)
            return asset

        new_asset = Asset(self, name=asset, confidentiality=confidentiality,
                          integrity=integrity, availability=availability)
        self._assets.add(new_asset)
        self.source.processes(new_asset)
        self.destination.processes(new_asset)
        return new_asset

    def is_relational_database_protocol(self) -> bool:
        return self.protocol in [
            Protocol.JDBC,
            Protocol.JDBC_ENCRYPTED,
            Protocol.ODBC,
            Protocol.ODBC_ENCRYPTED,
            Protocol.SQL,
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

    def data_flow_diagram(self, auto_view: bool = True,  hide_data_flow_labels: bool = False) -> None:
        diagram = DataFlowDiagram(self.name,
                                  hide_data_flow_labels=hide_data_flow_labels,
                                  )

        diagram.add_data_flow(self.source.id, self.destination.id,
                              lable=f"{self.protocol}: {self.name}",
                              bidirectional=self.bidirectional,
                              **self.overwrite_edge_attrs,
                              )

        diagram.add_asset(self.source.id, self.source.name,
                          self.source.shape, **self.source.overwrite_node_attrs)

        diagram.add_asset(self.destination.id, self.destination.name,
                          self.destination.shape, **self.destination.overwrite_node_attrs)

        if auto_view is False or self._model.is_ci():
            diagram.save()
            return

        if self._model.is_notebook():
            try:
                from IPython import display
                display.display(diagram)
            except ImportError:
                diagram.view()
        else:
            diagram.view()
