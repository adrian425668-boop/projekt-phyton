"""Modele danych i klasy domenowe wykorzystujące dekoratory metod."""

from collections import Counter
from collections.abc import Callable
import functools
from typing import Any, Self, TypeVar

M = TypeVar("M", bound=Callable[..., Any])


def require_loaded(method: M) -> M:
    """Dekorator metody sprawdzający, czy dane w obiekcie zostały wczytane."""

    @functools.wraps(method)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        if not getattr(self, "is_loaded", False):
            raise RuntimeError(
                f"Nie można wywołać '{method.__name__}' przed załadowaniem danych."
            )
        return method(self, *args, **kwargs)

    return wrapper  # type: ignore[return-value]


class AnalysisConfig:
    """Konfiguracja analizatora z walidacją za pomocą @property."""

    def __init__(self, min_status_code: int = 400, top_n: int = 5) -> None:
        self.min_status_code = min_status_code
        self.top_n = top_n

    @property
    def min_status_code(self) -> int:
        """Minimalny kod statusu HTTP kwalifikowany jako błąd."""
        return self._min_status_code

    @min_status_code.setter
    def min_status_code(self, value: int) -> None:
        if not (100 <= value <= 599):
            raise ValueError(f"Nieprawidłowy kod HTTP: {value}. Oczekiwano zakresu 100-599.")
        self._min_status_code = value

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Alternatywny konstruktor tworzący konfigurację ze słownika."""
        return cls(
            min_status_code=int(data.get("min_status_code", 400)),
            top_n=int(data.get("top_n", 5)),
        )

    @staticmethod
    def is_error_status(status_code: int) -> bool:
        """Sprawdza, czy kod statusu HTTP oznacza błąd klienta lub serwera."""
        return status_code >= 400


class LogReportSession:
    """Sesja raportowania chroniąca metody własnym dekoratorem @require_loaded."""

    def __init__(self, config: AnalysisConfig) -> None:
        self.config = config
        self.is_loaded: bool = False
        self._entries: list[dict[str, Any]] = []

    def load_entries(self, entries: list[dict[str, Any]]) -> None:
        """Ładuje sparsowane wpisy logów do sesji."""
        self._entries = entries
        self.is_loaded = True

    @require_loaded
    def top_client_ips(self) -> list[tuple[str, int]]:
        """Zwraca najaktywniejsze adresy IP."""
        counts = Counter(entry["ip"] for entry in self._entries)
        return counts.most_common(self.config.top_n)

    @require_loaded
    def detected_threats(self) -> dict[str, int]:
        """Zlicza wykryte kategorie podejrzanych żądań."""
        threats = Counter(
            entry["threat"] for entry in self._entries if entry.get("threat") is not None
        )
        return dict(threats)