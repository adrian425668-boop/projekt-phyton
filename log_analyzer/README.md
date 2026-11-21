Markdown
# Analizator logów serwera WWW

Projekt zaliczeniowy realizujący zagadnienia zaawansowanego programowania w języku Python 3.12+. Aplikacja generuje dane testowe w formacie Combined Log Format, strumieniowo parsuje i waliduje wpisy za pomocą własnych iteratorów, generatorów oraz wyrażeń regularnych, wykonuje równoległe obliczenia CPU-bound na wielu procesach, współbieżnie wzbogaca adresy IP (I/O-bound) oraz mierzy wpływ blokady GIL.

## Instrukcja uruchomienia

Wymagany interpreter: **Python 3.12+** (brak zależności zewnętrznych).

```bash
# Uruchomienie pełnej analizy i benchmarku GIL (40 000 linii logów)
python3 main.py --lines 40000 --workers 4

# Uruchomienie testów jednostkowych
python3 -m unittest discover -s tests -v