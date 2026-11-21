"""Własny iterator wczytujący pliki logów porcjami (chunkami)."""

from collections.abc import Iterator
from pathlib import Path
from typing import TextIO


class ChunkLogReader:
    """Iterator czytający plik tekstowy partiami po `chunk_size` linii."""

    def __init__(self, file_path: str | Path, chunk_size: int = 1000) -> None:
        if chunk_size < 1:
            raise ValueError("Parametr chunk_size musi być dodatni.")
        self.file_path = Path(file_path)
        if not self.file_path.is_file():
            raise FileNotFoundError(f"Plik logów nie istnieje: {self.file_path}")
        self.chunk_size = chunk_size
        self._file: TextIO | None = self.file_path.open("r", encoding="utf-8")

    def __iter__(self) -> Iterator[list[str]]:
        return self

    def __next__(self) -> list[str]:
        if self._file is None:
            raise StopIteration

        chunk: list[str] = []
        for _ in range(self.chunk_size):
            line = self._file.readline()
            if not line:
                break
            stripped = line.rstrip("\r\n")
            if stripped:
                chunk.append(stripped)

        if not chunk:
            self.close()
            raise StopIteration

        return chunk

    def close(self) -> None:
        """Zamyka uchwyt pliku, jeśli jest otwarty."""
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self) -> "ChunkLogReader":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()