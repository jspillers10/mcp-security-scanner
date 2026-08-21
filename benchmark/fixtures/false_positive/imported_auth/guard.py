"""A minimal fixture-only authorization decorator."""

from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T", bound=Callable[..., object])


def require_user(function: T) -> T:
    """Represent an external identity and policy check in this static fixture."""
    return function

