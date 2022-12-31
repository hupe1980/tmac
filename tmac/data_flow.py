from enum import Enum
from typing import TYPE_CHECKING, Dict, List, Set, Union, cast, overload

from .asset import Asset
from .diagram import DataFlowDiagram, DiagramEdge
from .element import Element
from .node import Construct
from .otm import OpenThreatModelDataFlow, OpenThreatModelThreatInstance
from .score import Score
from .tag import TagMixin

if TYPE_CHECKING:
    from .component import Component


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
        self,
        scope: Construct,
        name: str,
        *,
        source: "Component",
        destination: "Component",
        protocol: Protocol,
        description: str = "",
        vpn: bool = False,
        readonly: bool = False,
        bidirectional: bool = False,
        authentication: Authentication = Authentication.NONE,
        authorization: Authorization = Authorization.NONE,
        overwrite_edge_attrs: Dict[str, str] = dict(),
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

        self._overwrite_edge_attrs = overwrite_edge_attrs
        self._assets: Set["Asset"] = set()

    @property
    def assets(self) -> Set["Asset"]:
        return self._assets

    @property
    def max_average_asset_score(self) -> float:
        return cast(float, max([a.average_score for a in self.assets], default=0))

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
            # threats=[OpenThreatModelThreatInstance(
            #     r.id, str(r.treatment)) for r in self.risks],
            attributes={
                "protocol": str(self.protocol),
                "vpn": str(self.vpn),
                "readonly": str(self.readonly),
                "authentication": str(self.authentication),
                "authorization": str(self.authorization),
            },
        )

    @property
    def diagram_edge(self) -> "DiagramEdge":
        return DiagramEdge(
            self.source.id,
            self.destination.id,
            label=f"{self.protocol}: {self.name}",
            bidirectional=self.bidirectional,
            **self._overwrite_edge_attrs,
        )

    def validate(self) -> List[str]:
        if len(self.assets) == 0:
            return [f"Unnecessary Communication Link: {self.name}"]
        return []

    @overload
    def transfers(self, asset: "Asset") -> "Asset":
        ...

    @overload
    def transfers(
        self,
        asset: str,
        *,
        confidentiality: Score,
        integrity: Score,
        availability: Score,
    ) -> "Asset":
        ...

    def transfers(
        self,
        asset: Union["Asset", str],
        confidentiality: Score = Score.NONE,
        integrity: Score = Score.NONE,
        availability: Score = Score.NONE,
    ) -> "Asset":
        if isinstance(asset, Asset):
            self._assets.add(asset)
            self.source.processes(asset)
            self.destination.processes(asset)
            return asset

        new_asset = Asset(
            self,
            name=asset,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability,
        )
        self._assets.add(new_asset)
        self.source.processes(new_asset)
        self.destination.processes(new_asset)
        return new_asset

    @property
    def is_across_trust_boundary(self) -> bool:
        return self.source.trust_boundary != self.destination.trust_boundary

    @property
    def is_relational_database_protocol(self) -> bool:
        return self.protocol in [
            Protocol.JDBC,
            Protocol.JDBC_ENCRYPTED,
            Protocol.ODBC,
            Protocol.ODBC_ENCRYPTED,
            Protocol.SQL,
            Protocol.SQL_ENCRYPTED,
        ]

    @property
    def is_nosql_database_protocol(self) -> bool:
        return self.protocol in [
            Protocol.NOSQL,
            Protocol.NOSQL_ENCRYPTED,
        ]

    @property
    def is_web_access_protocol(self) -> bool:
        return self.protocol in [
            Protocol.HTTP,
            Protocol.HTTPS,
            Protocol.WS,
            Protocol.WSS,
        ]

    @property
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
            Protocol.SMB_ENCRYPTED,
            Protocol.SMTP_ENCRYPTED,
            Protocol.POP3_ENCRYPTED,
            Protocol.IMAP_ENCRYPTED,
        ]

    def create_data_flow_diagram(
        self, auto_view: bool = True, hide_data_flow_labels: bool = False
    ) -> None:
        diagram = DataFlowDiagram(
            self.name,
            is_notebook=self._model.is_notebook(),
            hide_data_flow_labels=hide_data_flow_labels,
        )

        diagram.add_node(self.source.diagram_node)
        diagram.add_node(self.destination.diagram_node)
        diagram.add_edge(self.diagram_edge)

        if auto_view is False or self._model.is_notebook() or self._model.is_ci():
            diagram.save()
            return

        diagram.show()
