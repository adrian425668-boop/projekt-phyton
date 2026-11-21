"""Potok przetwarzania oparty na generatorach (yield, yield from) i wyrażeniach generujących."""

from collections.abc import Iterable, Iterator
from pathlib import Path
import random
from typing import Any

from core.patterns import IPV4_STRICT_RE, LOG_LINE_RE, THREAT_PATTERN_RE


def generate_sample_log_file(output_path: str | Path, num_lines: int = 40_000) -> Path:
    """Generuje plik z przykładowymi danymi testowymi logów HTTP."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rng = random.Random(42)
    ips = [
        "192.168.1.10",
        "10.0.0.5",
        "172.16.0.22",
        "83.14.201.4",
        "185.220.101.1",
        "45.33.32.156",
    ]
    urls = [
        "/index.html",
        "/api/v1/users",
        "/login",
        "/products?id=10",
        "/../../etc/passwd",
        "/search?q=1+UNION+SELECT+password",
        "/wp-admin/setup-config.php",
    ]
    methods = ["GET", "POST", "PUT", "DELETE"]
    statuses = [200, 200, 200, 201, 304, 401, 403, 404, 500]

    with path.open("w", encoding="utf-8") as fh:
        for i in range(num_lines):
            if i % 2500 == 0 and i > 0:
                # Celowo uszkodzony wpis do przetestowania odporności parsera
                fh.write("USZKODZONY_WPIS_LOGU_BEZ_FORMATU\n")
                continue
            ip = rng.choice(ips)
            method = rng.choice(methods)
            url = rng.choice(urls)
            status = rng.choice(statuses)
            size = rng.randint(64, 16384)
            second = i % 60
            minute = (i // 60) % 60
            hour = (i // 3600) % 24
            fh.write(
                f'{ip} - - [17/Nov/2026:{hour:02d}:{minute:02d}:{second:02d} +0100] '
                f'"{method} {url} HTTP/1.1" {status} {size}\n'
            )

    return path


def read_lines_single(path: Path) -> Iterator[str]:
    """Generator czytający pojedynczy plik linia po linii."""
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            yield line.rstrip("\r\n")


def stream_multiple_files(paths: Iterable[Path]) -> Iterator[str]:
    """Generator delegujący odczyt z wielu plików przy użyciu `yield from`."""
    for path in paths:
        yield from read_lines_single(path)


def parse_log_stream(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Generator parsujący strumień linii logów do ustrukturyzowanych słowników."""
    for line in lines:
        match = LOG_LINE_RE.match(line)
        if not match:
            continue
        data = match.groupdict()
        if not IPV4_STRICT_RE.match(data["ip"]):
            continue

        threat_match = THREAT_PATTERN_RE.search(data["url"])
        yield {
            "ip": data["ip"],
            "date": data["date"],
            "method": data["method"],
            "url": data["url"],
            "status": int(data["status"]),
            "size": 0 if data["size"] == "-" else int(data["size"]),
            "threat": threat_match.group("threat").lower() if threat_match else None,
        }


def filter_error_entries(
    entries: Iterable[dict[str, Any]], min_status: int = 400
) -> Iterator[dict[str, Any]]:
    """Filtruje strumień wpisów przy użyciu wyrażenia generującego."""
    return (entry for entry in entries if entry["status"] >= min_status)