from typing import List, Optional

class SequenceDiagram:
    def __init__(self, title: str) -> None:
        self.title = title
        self._participants: List[str] = list()
        self._messages: List[str] = list()

        self._template = """@startuml {title}
{participants}
{messages}
@enduml"""

    def render(self) -> str:
        return self._template.format(
            title=self.title, 
            participants="\n".join(self._participants), 
            messages="\n".join(self._messages),
        )

    def add_actor(self, id: str, name: str) -> None:
        self._participants.append(f'actor {id} as "{name}"')

    def add_database(self, id: str, name: str) -> None:
        self._participants.append(f'database {id} as "{name}"')

    def add_entity(self, id: str, name: str) -> None:
        self._participants.append(f'entity {id} as "{name}"')

    def add_message(self, sender_id: str, receiver_id: str, request: str, response: Optional[str] = None) -> None:
        self._messages.append(f"{sender_id} -> {receiver_id}: {request}")
        if response:
            self._messages.append(f"{sender_id} <- {receiver_id}: {response}")

