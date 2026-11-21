"""Główny punkt wejścia aplikacji z interfejsem wiersza poleceń (argparse)."""

import argparse
import logging
from multiprocessing import cpu_count
from pathlib import Path

from benchmarks.gil_benchmark import get_gil_environment_info, run_gil_benchmark
from core.analyzer import analyze_file_multiprocess
from core.models import AnalysisConfig, LogReportSession
from core.pipeline import filter_error_entries, generate_sample_log_file
from core.reader import ChunkLogReader
from io_tasks.enricher import enrich_ips_multithreaded


def configure_logging(verbose: bool = False) -> None:
    """Konfiguruje format i poziom logowania."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )


def parse_args() -> argparse.Namespace:
    """Parsuje argumenty wiersza poleceń."""
    parser = argparse.ArgumentParser(
        description="Zaawansowany analizator logów serwera WWW z benchmarkiem GIL."
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("data/access.log"),
        help="Ścieżka do pliku logów (domyślnie: data/access.log)",
    )
    parser.add_argument(
        "--lines",
        type=int,
        default=40_000,
        help="Liczba linii do wygenerowania w pliku testowym (domyślnie: 40000)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=min(4, cpu_count()),
        help="Liczba procesów roboczych dla zadań CPU-bound",
    )
    parser.add_argument(
        "--skip-benchmark",
        action="store_true",
        help="Pomiń benchmark porównawczy GIL",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Włącz szczegółowe logowanie DEBUG",
    )
    return parser.parse_args()


def main() -> None:
    """Uruchamia pełny potok analizy logów, wzbogacania I/O oraz pomiaru GIL."""
    args = parse_args()
    configure_logging(args.verbose)
    logger = logging.getLogger("main")

    # 1. Generowanie danych testowych
    log_path = generate_sample_log_file(args.log_file, num_lines=args.lines)
    logger.info("Wygenerowano plik testowy: %s (%d linii)", log_path, args.lines)

    # 2. Równoległa analiza CPU-bound z użyciem procesów i własnego iteratora
    summary = analyze_file_multiprocess(
        log_path, chunk_size=5_000, max_workers=args.workers
    )

    # 3. Filtrowanie błędów za pomocą wyrażenia generującego i raportowanie domenowe
    config = AnalysisConfig.from_dict({"min_status_code": 400, "top_n": 5})
    error_count = sum(
        1 for _ in filter_error_entries(summary["entries"], config.min_status_code)
    )

    session = LogReportSession(config)
    session.load_entries(summary["entries"])

    print("\n=== PODSUMOWANIE ANALIZY LOGÓW ===")
    print(f"Poprawnie sparsowane wpisy : {summary['total_valid']}")
    print(f"Wpisy z błędami (>= {config.min_status_code})   : {error_count}")
    print(f"Rozkład kodów HTTP         : {summary['status_counts']}")
    print(f"Top adresy IP              : {session.top_client_ips()}")
    print(f"Wykryte próby ataków       : {session.detected_threats()}")

    # 4. Współbieżne wzbogacanie I/O (wątki + Lock + Queue + @retry)
    unique_ips = list(summary["ip_counts"].keys())
    enriched = enrich_ips_multithreaded(unique_ips, max_workers=6)
    print("\n=== WZBOGACANIE GEOIP (WĄTKI I/O) ===")
    for ip, meta in enriched.items():
        print(f"  {ip:<15} -> [{meta['country']}] {meta['org']}")

    # 5. Pomiar wpływu GIL (sekwencyjnie vs wątki vs procesy)
    if not args.skip_benchmark:
        env = get_gil_environment_info()
        with ChunkLogReader(log_path, chunk_size=5_000) as reader:
            chunks = list(reader)
        bench = run_gil_benchmark(chunks, workers=args.workers)

        print("\n=== BENCHMARK GIL (OBLICZENIA CPU-BOUND) ===")
        print(f"Środowisko : Python {env['python_version']} | GIL aktywny: {env['gil_enabled']}")
        print(f"Sekwencyjnie (1 wątek)     : {bench['sequential_s']:.4f} s")
        print(f"Wielowątkowo ({args.workers} wątki)    : {bench['threads_s']:.4f} s")
        print(f"Wieloprocesowo ({args.workers} proc.)  : {bench['processes_s']:.4f} s")
        print(f"Przyspieszenie procesów    : {bench['process_speedup']}x")


if __name__ == "__main__":
    main()