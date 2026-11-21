"""Współbieżne wzbogacanie adresów IP (zadania I/O-bound) z użyciem wątków, Lock i Queue."""

from concurrent.futures import ThreadPoolExecutor
import queue
import random
import threading
import time

from utils.decorators import measure_time, retry

_GEO_DB_MOCK: dict[str, dict[str, str]] = {
    "192.168.1.10": {"country": "LAN", "org": "Internal Network"},
    "10.0.0.5": {"country": "LAN", "org": "Internal VPN"},
    "172.16.0.22": {"country": "LAN", "org": "Staging Cluster"},
    "83.14.201.4": {"country": "PL", "org": "Orange Polska S.A."},
    "185.220.101.1": {"country": "DE", "org": "Tor Exit Node"},
    "45.33.32.156": {"country": "US", "org": "Linode / Akamai"},
}


@retry(attempts=3, delay=0.01, exceptions=(ConnectionError,))
def _simulated_network_lookup(ip: str) -> dict[str, str]:
    """Symuluje zapytanie sieciowe (I/O) z okresowym błędem połączenia."""
    time.sleep(0.08)  # Symulacja opóźnienia sieciowego (zwalnia GIL)
    if random.random() < 0.15:
        raise ConnectionError(f"Chwilowy timeout dla {ip}")
    return _GEO_DB_MOCK.get(ip, {"country": "UNKNOWN", "org": "Unregistered ASN"})


@measure_time
def enrich_ips_multithreaded(
    ip_addresses: list[str], max_workers: int = 6
) -> dict[str, dict[str, str]]:
    """Pobiera metadane dla listy adresów IP współbieżnie z synchronizacją Lock i Queue."""
    unique_ips = sorted(set(ip_addresses))
    results: dict[str, dict[str, str]] = {}
    results_lock = threading.Lock()
    audit_queue: queue.Queue[str | None] = queue.Queue()
    audit_log: list[str] = []

    def audit_consumer() -> None:
        while (message := audit_queue.get()) is not None:
            audit_log.append(message)
            audit_queue.task_done()
        audit_queue.task_done()

    consumer_thread = threading.Thread(target=audit_consumer, daemon=True)
    consumer_thread.start()

    def worker(ip: str) -> None:
        info = _simulated_network_lookup(ip)
        with results_lock:
            results[ip] = info
        audit_queue.put(f"Zakończono wzbogacanie IP: {ip} -> {info['country']}")

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        list(pool.map(worker, unique_ips))

    audit_queue.put(None)
    audit_queue.join()
    consumer_thread.join()

    return results