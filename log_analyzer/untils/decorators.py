"""Moduł zawierający własne dekoratory funkcji."""

from collections.abc import Callable
import functools
import logging
import time
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def measure_time(func: F) -> F:
    """Dekorator mierzący i logujący czas wykonania dekorowanej funkcji."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        logger.info("[%s] wykonano w %.4f s", func.__name__, elapsed)
        return result

    return wrapper  # type: ignore[return-value]


def retry(
    attempts: int = 3,
    delay: float = 0.02,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable[[F], F]:
    """Fabryka dekoratorów ponawiająca wywołanie funkcji w razie wystąpienia wyjątku."""
    if attempts < 1:
        raise ValueError("Liczba prób (attempts) musi być >= 1.")

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_error: Exception | None = None
            for attempt in range(1, attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_error = exc
                    logger.warning(
                        "[%s] Próba %d/%d nieudana: %s",
                        func.__name__,
                        attempt,
                        attempts,
                        exc,
                    )
                    if attempt < attempts:
                        time.sleep(delay)
            raise RuntimeError(
                f"{func.__name__}: wyczerpano limit {attempts} prób"
            ) from last_error

        return wrapper  # type: ignore[return-value]

    return decorator