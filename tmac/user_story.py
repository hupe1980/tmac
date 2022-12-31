import json
from typing import Dict, List, TYPE_CHECKING

from jinja2 import Template

if TYPE_CHECKING:
    from .risk import Risk


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
            if tpl.cwe_id in cwe_ids:
                tpls.append(tpl)
        return tpls





class UserStoryTemplate:
    def __init__(
        self,
        id: str,
        category: str,
        feature_name: str,
        description: str,
        text: str,
        cheat_sheet: str,
        cwe_id: int,
    ) -> None:
        self.id = id
        self.category = category,
        self.feature_name = feature_name
        self.description = description
        self.text = text
        self.cheat_sheet = cheat_sheet
        self.cwe_id = cwe_id


class UserStory:
    def __init__(
        self,
        template: "UserStoryTemplate",
        risk: "Risk",
    ) -> None:
        self._template = template
        self._risk = risk

    @property
    def id(self) -> str:
        return f"{self._template.id}@{self._risk.id}"

    @property
    def text(self) -> str:
        return Template(self._template.text).render()

    @property
    def references(self) -> List[str]:
        return [self._template.cheat_sheet, f"https://cwe.mitre.org/data/definitions/{self._template.cwe_id}.html"]

