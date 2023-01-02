import json
from abc import ABC, abstractproperty
from enum import Enum
from typing import TYPE_CHECKING, Dict, Generic, List, TypeVar

from jinja2 import Template

if TYPE_CHECKING:
    from .risk import ComponentRisk, ModelRisk


class ASVSCategory(str, Enum):
    RESTFUL_WEB_SERVICE = "RESTful Web Service"
    SOAP_WEB_SERVICE = "SOAP Web Service"


class UserStoryTemplateRepository:
    @staticmethod
    def fromFile(filename: str) -> "UserStoryTemplateRepository":
        repostiroy = UserStoryTemplateRepository()

        with open(filename, "r", encoding="utf8") as tpl_file:
            tpl_json = json.load(tpl_file)

        for tpl in tpl_json:
            repostiroy.add_templates(UserStoryTemplate(**tpl))

        return repostiroy

    def __init__(self) -> None:
        self._lib: Dict[str, "UserStoryTemplate"] = dict()

    def add_templates(self, *templates: "UserStoryTemplate") -> None:
        for template in templates:
            self._lib[template.id] = template

    def get_by_id(self, id: str) -> "UserStoryTemplate":
        return self._lib[id]

    def get_all(self) -> List["UserStoryTemplate"]:
        return list(self._lib.values())

    def get_by_cwe(self, *cwe_ids: int) -> List["UserStoryTemplate"]:
        tpls: List["UserStoryTemplate"] = list()
        for tpl in self._lib.values():
            if any(x in tpl.cwe_ids for x in cwe_ids):
                tpls.append(tpl)
        return tpls


class UserStoryTemplate:
    def __init__(
        self,
        id: str,
        category: str,
        sub_category: str,
        description: str,
        feature_name: str,
        user_story: str,
        scenarios: Dict[str, str],
        references: List[str],
        cwe_ids: List[int],
        nist: List[str],
        tags: List[str],
    ) -> None:
        self.id = id
        self.category = category
        self.sub_category = sub_category
        self.description = description
        self.feature_name = feature_name
        self.user_story = user_story
        self.scenarios = scenarios
        self.references = references
        self.cwe_ids = cwe_ids
        self.nist = nist
        self.tags = tags


T = TypeVar("T")


class UserStory(Generic[T]):
    def __init__(
        self,
        template: "UserStoryTemplate",
        risk: "T",
    ) -> None:
        self._template = template
        self._risk = risk

    @abstractproperty
    def id(self) -> str:
        pass

    @abstractproperty
    def text(self) -> str:
        pass

    @property
    def description(self) -> str:
        return self._template.description

    @property
    def category(self) -> str:
        return self._template.category

    @property
    def sub_category(self) -> str:
        if self._template.sub_category == "":
            return self._template.category
        return self._template.sub_category

    @property
    def feature_name(self) -> str:
        return self._template.feature_name

    @property
    def scenarios(self) -> Dict[str, str]:
        return self._template.scenarios

    @property
    def references(self) -> List[str]:
        return [
            *self._template.references,
            *[
                f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                for cwe_id in self._template.cwe_ids
            ],
        ]


class ComponentUserStory(UserStory["ComponentRisk"]):
    def __init__(
        self,
        template: "UserStoryTemplate",
        risk: "ComponentRisk",
    ) -> None:
        super().__init__(template, risk)

    @property
    def id(self) -> str:
        return f"{self._template.id}@{self._risk.id}"

    @property
    def text(self) -> str:
        if self._template.user_story == "TODO":
            return self.description

        return Template(self._template.user_story).render(
            component=self._risk.component,
            data_flow=self._risk.data_flow,
            model=self._risk.model,
        )


class ModelUserStory(UserStory["ModelRisk"]):
    def __init__(
        self,
        template: "UserStoryTemplate",
        risk: "ModelRisk",
    ) -> None:
        super().__init__(template, risk)

    @property
    def id(self) -> str:
        return f"{self._template.id}@{self._risk.id}"

    @property
    def text(self) -> str:
        if self._template.user_story == "TODO":
            return self.description

        return Template(self._template.user_story).render(model=self._risk.model)
