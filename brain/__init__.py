from importlib import import_module
from typing import TYPE_CHECKING, Any

# Avoid importing heavy modules at package import time.
# Provide lazy attributes so `from brain import Brain` still works.

if TYPE_CHECKING:  # for type checkers only
    from .brain import Brain as Brain  # type: ignore
    from .brain_singleton import get_brain as get_brain  # type: ignore

__all__ = ["Brain", "get_brain"]

def __getattr__(name: str) -> Any:
    if name == "Brain":
        return import_module(".brain", __name__).Brain
    if name == "get_brain":
        return import_module(".brain_singleton", __name__).get_brain
    raise AttributeError(f"module 'brain' has no attribute {name!r}")
