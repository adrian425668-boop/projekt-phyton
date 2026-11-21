"""Przetwarzanie równoległe zadań obliczeniowych (CPU-bound) z użyciem procesów."""

from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import cpu_count
from pathlib import Path
from typing import Any

from core.pipeline import parse_log_stream
from core.reader import ChunkLogReader
from utils.decorators import measure_time


def _cpu_checksum(payload: str) -> int:
    """Obliczenia wielomianowe w czystym Pythonie (obciążenie CPU dla testów GIL)."""
    acc = 0
    for idx, ch in enumerate(payload):
        acc = (acc * 31 + ord(ch) + idx) % 1_000_000_007
    return acc


def process_log_chunk_cpu(lines: list[str]) -> dict[str, Any]:
    """Funkcja robocza dla puli procesów: parsuje porcję logów i liczy sygnatury CPU."""
    status_counts: Counter[int] = Counter()
    ip_counts: Counter[str] = Counter()
    threat_counts: Counter[str] = Counter()
    parsed_entries: list[dict[str, Any]] = []
    checksum_xor = 0

    for entry in parse_log_stream(lines):
        status_counts[entry["status"]] += 1
        ip_counts[entry["ip"]] += 1
        if entry["threat"]:
            threat_counts[entry["threat"]] += 1
        checksum_xor ^= _cpu_checksum(f"{entry['ip']}:{entry['url']}:{entry['date']}")
        parsed_entries.append(entry)

    return {
        "valid_count": len(parsed_entries),
        "status_counts": dict(status_counts),
        "ip_counts": dict(ip_counts),
        "threat_counts": dict(threat_counts),
        "checksum_xor": checksum_xor,
        "entries": parsed_entries,
    }


@measure_time
def analyze_file_multiprocess(
    file_path: str | Path,
    chunk_size: int = 5_000,
    max_workers: int | None = None,
) -> dict[str, Any]:
    """Dzieli plik logów iteratorem ChunkLogReader i przetwarza porcje równolegle."""
    workers = max_workers or min(4, cpu_count())
    with ChunkLogReader(file_path, chunk_size=chunk_size) as reader:
        chunks = list(reader)

    total_status: Counter[int] = Counter()
    total_ips: Counter[str] = Counter()
    total_threats: Counter[str] = Counter()
    all_entries: list[dict[str, Any]] = []
    combined_checksum = 0

    with ProcessPoolExecutor(max_workers=workers) as executor:
        for partial in executor.map(process_log_chunk_cpu, chunks):
            total_status.update(partial["status_counts"])
            total_ips.update(partial["ip_counts"])
            total_threats.update(partial["threat_counts"])
            combined_checksum ^= partial["checksum_xor"]
            all_entries.extend(partial["entries"])

    return {
        "total_valid": len(all_entries),
        "status_counts": dict(sorted(total_status.items())),
        "ip_counts": dict(total_ips),
        "threat_counts": dict(total_threats),
        "combined_checksum": combined_checksum,
        "entries": all_entries,
    }