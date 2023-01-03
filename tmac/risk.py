from abc import ABC, abstractproperty
from typing import TYPE_CHECKING, List, Optional, Set, cast

from jinja2 import Template

from .threat import ComponentThreat, ModelThreat
from .user_story import ComponentUserStory, ModelUserStory, UserStory

if TYPE_CHECKING:
    from .component import Component
    from .data_flow import DataFlow
    from .model import Model
    from .threat import BaseThreat, Category

class RiskTreatment:
    def __init__(self, state: str, *, ticket: str = "", comment: str = "") -> None:
        self.state = state
        self.ticket = ticket
        self.comment = comment

class Risk(ABC):
    def __init__(
        self,
        threat: "BaseThreat",
        model: "Model",
    ) -> None:
        self._threat = threat
        self._model = model
        self._treatment = RiskTreatment("unchecked")

    @abstractproperty
    def id(self) -> str:
        pass

    @abstractproperty
    def text(self) -> str:
        pass

    @abstractproperty
    def user_stories(self) -> List["UserStory[Risk]"]:
        pass

    @property
    def name(self) -> str:
        return self._threat.name

    @property
    def description(self) -> str:
        return self._threat.description

    @property
    def prerequisites(self) -> List[str]:
        return self._threat.prerequisites

    @property
    def category(self) -> "Category":
        return self._threat.category

    @property
    def references(self) -> List[str]:
        return [
            *self._threat.references,
            *[
                f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                for cwe_id in self._threat.cwe_ids
            ],
        ]

    @property
    def model(self) -> "Model":
        return self._model

    @property
    def treatment(self) -> "RiskTreatment":
        if self._treatment.state != "unchecked":
            return self._treatment
        
        if all(story.state in ["closed"] for story in self.user_stories):
            return RiskTreatment("mitigated", comment="All user stories are closed")

        if any(story.state != "draft" for story in self.user_stories):
            return RiskTreatment("in-progress")

        return self._treatment

    def update_treatment(self, state: str, *, ticket: str = "", comment: str = "") -> None:
        self._treatment = RiskTreatment(state, ticket=ticket, comment=comment)


class ComponentRisk(Risk):
    def __init__(
        self,
        threat: "BaseThreat",
        *,
        model: "Model",
        component: "Component",
        data_flow: Optional["DataFlow"] = None,
    ) -> None:
        super().__init__(threat=threat, model=model)

        self._component = component
        self._data_flow = data_flow

    @property
    def id(self) -> str:
        if self._data_flow is not None:
            return f"{self._threat.id}@{self._component.name}@{self._data_flow.name}"
        return f"{self._threat.id}@{self._component.name}"

    @property
    def text(self) -> str:
        return Template(self._threat.risk_text).render(
            component=self._component, data_flow=self._data_flow, model=self._model
        )

    @property
    def component(self) -> "Component":
        return self._component

    @property
    def data_flow(self) -> Optional["DataFlow"]:
        return self._data_flow

    @property
    def user_stories(self) -> List["UserStory[Risk]"]:
        if self._treatment.state in ["accepted", "transferred", "n/a", "mitigated"]:
            return []

        stories: Set["ComponentUserStory"] = set()
        if isinstance(self._threat, ComponentThreat):
            for tpl in self._threat.get_user_story_templates(
                self._model.user_story_template_repository, self._component
            ):
                id = f"{tpl.id}@{self.id}"
                user_story = ComponentUserStory(id=id, template=tpl, risk=self)

                new_state = self._model.get_state_by_id(id)
                if new_state is not None:
                    user_story.update_state(
                        state=new_state.state,
                        ticket=new_state.ticket,
                        comment=new_state.comment,
                    )

                stories.add(user_story)
            return cast(List["UserStory[Risk]"], list(stories))

        return NotImplemented


class ModelRisk(Risk):
    def __init__(
        self,
        threat: "BaseThreat",
        model: "Model",
    ) -> None:
        super().__init__(threat=threat, model=model)

    @property
    def id(self) -> str:
        return f"{self._threat.id}@model"

    @property
    def text(self) -> str:
        return Template(self._threat.risk_text).render(model=self._model)

    @property
    def user_stories(self) -> List["UserStory[Risk]"]:
        stories: Set["ModelUserStory"] = set()

        if isinstance(self._threat, ModelThreat):
            for tpl in self._threat.get_user_story_templates(
                self._model.user_story_template_repository
            ):
                id = f"{tpl.id}@{self.id}"
                user_story = ModelUserStory(id=id, template=tpl, risk=self)

                new_state = self._model.get_state_by_id(id)
                if new_state is not None:
                    user_story.update_state(
                        state=new_state.state,
                        ticket=new_state.ticket,
                        comment=new_state.comment,
                    )

                stories.add(user_story)
            return cast(List["UserStory[Risk]"], list(stories))

        return NotImplemented
