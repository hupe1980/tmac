import uuid
from re import sub

def unique_id(name: str) -> str:
    uid = str(uuid.uuid4())[:8]
    return kebab_case(f"{name}-{uid}") 

def kebab_case(s: str) -> str:
  return '-'.join(
    sub(r"(\s|_|-)+"," ",
    sub(r"[A-Z]{2,}(?=[A-Z][a-z]+[0-9]*|\b)|[A-Z]?[a-z]+[0-9]*|[A-Z]|[0-9]+",
    lambda mo: " " + str(mo.group(0).lower()), s)).split())
