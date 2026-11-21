# Analizator logów serwera WWW

## Opis projektu i instrukcja uruchomienia

Projekt zaliczeniowy z przedmiotu *Zaawansowane techniki programowania w języku Python* (wymagania: Python 3.12+, przetestowany w środowisku CPython 3.14.0). Aplikacja realizuje wieloetapowy potok przetwarzania logów serwera WWW w formacie Combined Log Format: generuje dane testowe wraz z celowo wprowadzonymi uszkodzonymi wpisami, strumieniowo wczytuje i parsuje logi z wykorzystaniem własnego iteratora, generatorów oraz wyrażeń regularnych, wykonuje równoległe obliczenia CPU-bound na wielu procesach, współbieżnie wzbogaca adresy IP (I/O-bound) z użyciem puli wątków oraz przeprowadza pomiar porównawczy wpływu blokady GIL.

Projekt wykorzystuje wyłącznie bibliotekę standardową Pythona (brak zewnętrznych zależności w pliku `requirements.txt`).

### Struktura modułów

* `main.py` – punkt wejścia aplikacji z obsługą argumentów wiersza poleceń (`argparse`) oraz konfiguracją logowania (`logging`).
* `requirements.txt` – informacja o braku zewnętrznych zależności (czysta biblioteka standardowa).
* `utils/decorators.py` – własne dekoratory funkcji (`@measure_time`, `@retry`).
* `core/patterns.py` – skompilowane wyrażenia regularne z grupami nazwanymi (`LOG_LINE_RE`, `IPV4_STRICT_RE`, `THREAT_PATTERN_RE`).
* `core/models.py` – modele domenowe z walidacją i dekoratorami metod (`@require_loaded`, `@property`, `@classmethod`, `@staticmethod`).
* `core/reader.py` – własny iterator blokowy (`ChunkLogReader`) obsługujący protokół menedżera kontekstu.
* `core/pipeline.py` – generator danych testowych oraz strumieniowy potok przetwarzania (`yield`, `yield from`, wyrażenia generujące).
* `core/analyzer.py` – równoległa analiza danych CPU-bound przy użyciu puli procesów (`ProcessPoolExecutor`).
* `io_tasks/enricher.py` – współbieżne wzbogacanie adresów IP I/O-bound (`ThreadPoolExecutor`, `threading.Lock`, `queue.Queue`).
* `benchmarks/gil_benchmark.py` – moduł porównujący wydajność wykonania sekwencyjnego, wielowątkowego i wieloprocesowego.
* `tests/test_analyzer.py` – zestaw testów jednostkowych (`unittest`).

### Instrukcja uruchomienia

```bash
# Uruchomienie pełnej analizy logów, wzbogacania GeoIP oraz benchmarku GIL (domyślnie 40 000 linii)
python main.py

# Uruchomienie z własnymi parametrami CLI
python main.py --lines 100000 --workers 4 --verbose

# Uruchomienie zestawu testów jednostkowych
python -m unittest discover -s tests -v
```

## Tabela mapowania zagadnień

| Zagadnienie | Gdzie w kodzie (plik → klasa / funkcja) |
| :--- | :--- |
| **Dekoratory funkcji** (`functools.wraps`, prosty oraz z parametrami) | `utils/decorators.py` → `measure_time()`, `retry(attempts, delay, exceptions)` |
| **Dekoratory metod** (korzystający z `self` oraz wbudowane `@property`, `@classmethod`, `@staticmethod`) | `core/models.py` → `require_loaded()` w klasie `LogReportSession`; `AnalysisConfig` (`@property`, `@min_status_code.setter`, `@classmethod` `from_dict`, `@staticmethod` `is_error_status`) |
| **Iteratory** (własna klasa z `__iter__` i `__next__`) | `core/reader.py` → klasa `ChunkLogReader` |
| **Generatory** (`yield`, `yield from` oraz wyrażenia generujące) | `core/pipeline.py` → `read_lines_single()`, `stream_multiple_files()`, `parse_log_stream()`, `filter_error_entries()` |
| **Wyrażenia regularne** (walidacja i ekstrakcja z grupami nazwanymi) | `core/patterns.py` → `LOG_LINE_RE`, `IPV4_STRICT_RE`, `THREAT_PATTERN_RE` |
| **Wątki (I/O-bound)** (współbieżność i synchronizacja `Lock` / `Queue`) | `io_tasks/enricher.py` → `enrich_ips_multithreaded()`, `_simulated_network_lookup()` (`ThreadPoolExecutor`, `threading.Lock`, `queue.Queue`) |
| **Procesy (CPU-bound)** (równoległe przetwarzanie obliczeń) | `core/analyzer.py` → `analyze_file_multiprocess()`, `process_log_chunk_cpu()` (`ProcessPoolExecutor`) |
| **Pomiar wpływu GIL** (sekwencyjnie vs wątki vs procesy) | `benchmarks/gil_benchmark.py` → `run_gil_benchmark()`, `get_gil_environment_info()` |
| **Elementy dodatkowe** (CLI, `logging`, testy jednostkowe) | `main.py` → `parse_args()`, `configure_logging()`; `tests/test_analyzer.py` → `TestAdvancedPythonProject` |

## Wyniki pomiarów wydajności i wnioski dotyczące GIL

Pomiary przeprowadzono na środowisku **CPython 3.14.0** z aktywną blokadą GIL (`GIL aktywny: True`) dla wygenerowanego zbioru **40 000 linii logów** (z czego 39 985 wpisów przeszło walidację formatu, a 15 uszkodzonych linii zostało odrzuconych przez parser).

### Porównanie trybów wykonania dla zadania obliczeniowego (CPU-bound)

| Tryb wykonania | Liczba workerów | Czas wykonania [s] | Przyspieszenie względem wersji sekwencyjnej |
| :--- | :---: | :---: | :---: |
| Sekwencyjnie (1 wątek) | 1 | 0.2127 s | 1.00x |
| Wielowątkowo (`ThreadPoolExecutor`) | 4 | 0.2140 s | 0.99x |
| Wieloprocesowo (`ProcessPoolExecutor`) | 4 | 0.1900 s | 1.12x |

### Czasy wykonania głównych etapów aplikacji (zmierzone dekoratorem `@measure_time`)

| Etap przetwarzania | Typ zadania | Konfiguracja | Czas wykonania [s] |
| :--- | :---: | :---: | :---: |
| `analyze_file_multiprocess` (parsowanie i sumy kontrolne) | CPU-bound | 4 procesy | 0.2188 s |
| `enrich_ips_multithreaded` (wzbogacanie GeoIP + `@retry`) | I/O-bound | 6 wątków | 0.1723 s |

### Wnioski dotyczące GIL

Pomiary wykonano w środowisku CPython 3.14.0 z włączoną blokadą GIL (`GIL aktywny: True`) dla paczek danych podzielonych po 5 000 linii. W standardowym interpreterze CPython mechanizm Global Interpreter Lock wymusza, aby w danej chwili tylko jeden wątek wykonywał kod bajtowy Pythona, nawet na procesorze wielordzeniowym. Z tego powodu w zadaniach czysto obliczeniowych (CPU-bound), takich jak dopasowywanie wyrażeń regularnych i obliczanie wielomianowych sum kontrolnych, uruchomienie 4 wątków (`0.2140 s`) nie dało przyspieszenia względem wersji sekwencyjnej (`0.2127 s`), a minimalny spadek wydajności wynika z narzutu interpretera na przełączanie kontekstu między wątkami rywalizującymi o dostęp do GIL. Zastosowanie 4 procesów (`ProcessPoolExecutor`) uruchamia niezależne interpretery z własnymi przestrzeniami pamięci i osobnymi instancjami GIL, umożliwiając prawdziwe zrównoleglenie obliczeń na wielu rdzeniach CPU. Przy próbce 40 000 linii wykonanie wieloprocesowe skróciło czas do `0.1900 s` (przyspieszenie `1.12x`), ponieważ w systemie Windows procesy potomne tworzone są metodą `spawn`, której koszt uruchomienia stanowi zauważalną część krótkich obliczeń. Wraz ze wzrostem liczby analizowanych linii czas obliczeń coraz wyraźniej dominuje nad narzutem startu procesów, zwiększając przewagę `ProcessPoolExecutor`. Odwrotną sytuację zaobserwowano w module `io_tasks/enricher.py` realizującym zadania I/O-bound, gdzie podczas oczekiwania na symulowaną odpowiedź sieciową interpreter zwalnia GIL, dzięki czemu 6 wątków pobrało metadane dla wszystkich 6 unikalnych adresów IP (wraz z automatycznym ponowieniem 3 pojedynczych timeoutów przez dekorator `@retry`) w czasie `0.1723 s`.

## Napotkane problemy w trakcie realizacji

1. **Serializacja zadań (`pickle`) i tryb `spawn` w systemie Windows:** W systemie Windows procesy potomne w `ProcessPoolExecutor` uruchamiane są metodą `spawn`, co powoduje ponowne importowanie modułów oraz konieczność serializacji przekazywanych funkcji przez `pickle`. Wymusiło to zdefiniowanie funkcji roboczej `process_log_chunk_cpu` na najwyższym poziomie modułu `core/analyzer.py` oraz zabezpieczenie punktu uruchomienia w `main.py` blokiem `if __name__ == "__main__":`.
2. **Konfiguracja katalogu roboczego i ścieżek importów w IDE:** Uruchamianie testów jednostkowych z poziomu nadrzędnego katalogu zamiast bezpośrednio z folderu projektu `log_analyzer` skutkowało błędami `ModuleNotFoundError` podczas importowania pakietów `core` oraz `utils`. Problem rozwiązano poprzez ujednolicenie struktury katalogów projektu oraz ustawienie głównego folderu `log_analyzer` jako `Sources Root` w PyCharmie.
3. **Bezpośrednie uruchamianie plików z podpakietów:** Próba bezpośredniego uruchomienia modułu wewnętrznego (`core/analyzer.py`) kończyła się błędem `ModuleNotFoundError: No module named 'core'`, ponieważ Python traktował wówczas podkatalog `core` jako główny katalog roboczy. Wszystkie scenariusze uruchomieniowe oraz testy oparto więc na wywołaniach z poziomu katalogu głównego (`main.py` oraz `python -m unittest discover -s tests`).
4. **Bezpieczne zamykanie uchwytów plików we własnym iteratorze:** W klasie `ChunkLogReader` zamykanie pliku dopiero w momencie zgłoszenia wyjątku `StopIteration` nie chroniłoby przed wyciekiem uchwytu w razie wcześniejszego przerwania pętli, dlatego zaimplementowano dodatkowo protokół menedżera kontekstu (`__enter__`, `__exit__`).