from typing import TYPE_CHECKING, List, Set

from jinja2 import Template

from .threat import ComponentThreat, ModelThreat
from .user_story import UserStory

if TYPE_CHECKING:
    from .component import TechnicalComponent
    from .model import Model
    from .threat import BaseThreat, Stride
    


class Risk:
    def __init__(
        self, component: "TechnicalComponent", threat: "BaseThreat", model: "Model"
    ) -> None:
        self._component = component
        self._threat = threat
        self._model = model

    @property
    def id(self) -> str:
        return f"{self._threat.id}@{self._component.name}"

    @property
    def name(self) -> str:
        return self._threat.name

    @property
    def text(self) -> str:
        return Template(self._threat.risk_text).render(component=self._component, model=self._model)

    @property
    def stride(self) -> "Stride":
        return self._threat.stride

    @property
    def user_stories(self) -> List["UserStory"]:
        stories: Set["UserStory"] = set()
        if isinstance(self._threat, ComponentThreat):
            for tpl in self._threat.get_user_story_templates(
                self._model.user_story_template_repository, self._component
            ):
                stories.add(UserStory(tpl, self))
            return list(stories)

        if isinstance(self._threat, ModelThreat):
            for tpl in self._threat.get_user_story_templates(
                self._model.user_story_template_repository
            ):
                stories.add(UserStory(tpl, self))
            return list(stories)

        return NotImplemented
