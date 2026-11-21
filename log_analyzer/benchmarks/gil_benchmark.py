"""Benchmark porównawczy wpływu GIL: wykonanie sekwencyjne vs wątki vs procesy."""

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import sys
import sysconfig
import time

from core.analyzer import process_log_chunk_cpu


def get_gil_environment_info() -> dict[str, str | bool]:
    """Zwraca informacje o interpreterze i stanie blokady GIL."""
    gil_enabled = True
    if hasattr(sys, "_is_gil_enabled"):
        gil_enabled = bool(sys._is_gil_enabled())
    return {
        "python_version": sys.version.split()[0],
        "switch_interval_s": str(sys.getswitchinterval()),
        "free_threading_build": bool(sysconfig.get_config_var("Py_GIL_DISABLED")),
        "gil_enabled": gil_enabled,
    }


def run_gil_benchmark(chunks: list[list[str]], workers: int = 4) -> dict[str, float]:
    """Mierzy czas wykonania zadania CPU-bound trzema metodami."""
    # 1. Wykonanie sekwencyjne (1 wątek, 1 proces)
    start = time.perf_counter()
    seq_results = [process_log_chunk_cpu(chunk) for chunk in chunks]
    seq_time = time.perf_counter() - start

    # 2. Wykonanie wielowątkowe (ograniczone przez GIL w CPython)
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as thread_pool:
        thr_results = list(thread_pool.map(process_log_chunk_cpu, chunks))
    thr_time = time.perf_counter() - start

    # 3. Wykonanie wieloprocesowe (osobne interpretery i GIL na każdym rdzeniu)
    start = time.perf_counter()
    with ProcessPoolExecutor(max_workers=workers) as proc_pool:
        proc_results = list(proc_pool.map(process_log_chunk_cpu, chunks))
    proc_time = time.perf_counter() - start

    # Weryfikacja spójności wyników
    assert sum(r["valid_count"] for r in seq_results) == sum(
        r["valid_count"] for r in thr_results
    ) == sum(r["valid_count"] for r in proc_results)

    return {
        "sequential_s": round(seq_time, 4),
        "threads_s": round(thr_time, 4),
        "processes_s": round(proc_time, 4),
        "process_speedup": round(seq_time / proc_time, 2) if proc_time > 0 else 0.0,
    }