from typing import List, TypeVar

T = TypeVar('T')

def issublist(lst1: List[T], lst2: List[T]) -> bool:
    return all([(x in lst2) for x in lst1])