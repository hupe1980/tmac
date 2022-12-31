import os
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Iterable, cast

from jinja2 import Template
from tabulate import tabulate

from .asset import Asset
from .component import Component, TechnicalComponent
from .data_flow import DataFlow
from .diagram import DataFlowDiagram
from .node import Construct, unique_id
from .otm import OpenThreatModel, OpenThreatModelProject
from .table_format import TableFormat
from .tag import TagMixin
from .threat import ThreatLibrary
from .threat_library import (
    DEFAULT_THREAT_LIBRARY,
    DEFAULT_USER_STORY_TEMPLATE_REPOSITORY,
)
from .user_story import UserStoryTemplateRepository

if TYPE_CHECKING:
    from .risk import Risk
    from .user_story import UserStory


class ModelException(Exception):
    pass


class Model(Construct, TagMixin):
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

    def __init__(
        self,
        name: str,
        *,
        description: str = "",
        owner: str = "",
        owner_contact: str = "",
        auto_evaluate: bool = True,
        skip_validation: bool = False,
        user_story_template_repository: Optional["UserStoryTemplateRepository"] = None,
        threat_library: Optional["ThreatLibrary"] = None,
    ) -> None:
        super().__init__(None, unique_id(name))

        self.name = name
        self.description = description
        self.owner = owner
        self.owner_contact = owner_contact
        self.auto_evaluate = auto_evaluate
        self.skip_validation = skip_validation

        if user_story_template_repository is None:
            self.user_story_template_repository = DEFAULT_USER_STORY_TEMPLATE_REPOSITORY
        else:
            self.user_story_template_repository = user_story_template_repository

        if threat_library is None:
            self.threat_library = DEFAULT_THREAT_LIBRARY
        else:
            self.threat_library = threat_library

        self._risks: Dict[str, "Risk"] = dict()

    @property
    def assets(self) -> List["Asset"]:
        return cast(
            List["Asset"],
            list(filter(lambda c: isinstance(c, Asset), self.node.find_all())),
        )

    @property
    def components(self) -> List["Component"]:
        return cast(
            List["Component"],
            list(filter(lambda c: isinstance(c, Component), self.node.find_all())),
        )

    @property
    def data_flows(self) -> List["DataFlow"]:
        return cast(
            List["DataFlow"],
            list(filter(lambda c: isinstance(c, DataFlow), self.node.find_all())),
        )

    @property
    def risks(self) -> List["Risk"]:
        if self.auto_evaluate:
            self.evaluate()
        return list(self._risks.values())

    @property
    def user_stories(self) -> List["UserStory"]:
        stories: Set["UserStory"] = set()
        for risk in self.risks:
            for story in risk.user_stories:
                stories.add(story)

        return list(stories)

    @property
    def otm(self) -> "OpenThreatModel":
        return OpenThreatModel(
            project=OpenThreatModelProject(name=self.name, id=self.id),
            assets=[a.otm for a in self.assets],
            components=[c.otm for c in self.components],
            data_flows=[df.otm for df in self.data_flows],
            # threats=[r.otm for r in self.risks],
            # mitigations=[m.otm for m in self.mitigations],
        )

    def is_notebook(self) -> bool:
        try:
            shell = get_ipython().__class__.__name__  # type: ignore
            if shell == "ZMQInteractiveShell":
                return True  # Jupyter notebook or qtconsole
            elif shell == "TerminalInteractiveShell":
                return False  # Terminal running IPython
            else:
                return False  # Other type (?)
        except NameError:
            return False  # Probably standard Python interpreter

    def is_ci(self) -> bool:
        return os.environ.get("CI") is not None

    def create_risks_table(self, table_format: TableFormat = TableFormat.SIMPLE) -> str:
        headers = ["ID", "Risk"]
        table = []
        for risk in self.risks:
            table.append([risk.id, risk.text])

        return tabulate(table, headers=headers, tablefmt=str(table_format))

    def create_backlog_table(
        self, table_format: TableFormat = TableFormat.SIMPLE
    ) -> str:
        headers = ["ID", "User Story"]
        table = []
        for user_story in self.user_stories:
            table.append([user_story.id, user_story.text])

        maxcolwodths: Optional[Iterable[int | None]]=[None, 80]
        if table_format == TableFormat.GITHUB:
            maxcolwodths = None

        return tabulate(
            table, headers=headers, tablefmt=str(table_format), maxcolwidths=maxcolwodths
        )

    def create_report(self) -> None:
        with open(
            os.path.dirname(__file__) + "/templates/default.tpl", "r", encoding="utf8"
        ) as tpl_file:
            template = Template(tpl_file.read())

        with open("report.md", "w+") as f:
            f.write(template.render(model=self))

    def create_data_flow_diagram(
        self,
        auto_view: bool = True,
        hide_data_flow_labels: bool = False,
    ) -> None:
        diagram = DataFlowDiagram(
            self.name,
            is_notebook=self.is_notebook(),
            hide_data_flow_labels=hide_data_flow_labels,
        )
        for c in self.components:
            diagram.add_node(c.diagram_node)

        for df in self.data_flows:
            diagram.add_edge(df.diagram_edge)

        if auto_view is False or self.is_notebook() or self.is_ci():
            diagram.save()
            return

        diagram.show()

    def evaluate(self) -> None:
        self.node.lock()
        if not self.skip_validation:
            exceptions: List["ModelException"] = list()
            for c in self.node.find_all():
                errors = c.node.validate()
                for error in errors:
                    exceptions.append(ModelException(error))
            if len(exceptions) > 0:
                raise ExceptionGroup("Validation errors", exceptions)

        self._risks = dict()
        for c in self.components:
            if not isinstance(c, TechnicalComponent):
                continue
            for risk in c.risks:
                self._risks[risk.id] = risk

        self.node.unlock()
