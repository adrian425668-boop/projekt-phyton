"""Skompilowane wyrażenia regularne z grupami nazwanymi do parsowania i walidacji logów."""

import re

# Wzorzec 1: Parsowanie wpisu logu HTTP (Combined Log Format) z grupami nazwanymi
LOG_LINE_RE: re.Pattern[str] = re.compile(
    r"""
    ^
    (?P<ip>\d{1,3}(?:\.\d{1,3}){3})          # Adres IPv4 klienta
    \s-\s-\s
    \[(?P<date>[^\]]+)\]                     # Znacznik czasu w nawiasach kwadratowych
    \s"(?P<method>GET|POST|PUT|DELETE|HEAD)  # Metoda HTTP
    \s(?P<url>\S+)                           # Ścieżka żądania
    \sHTTP/\d\.\d"                           # Wersja protokołu
    \s(?P<status>\d{3})                      # Kod odpowiedzi HTTP
    \s(?P<size>\d+|-)                        # Rozmiar odpowiedzi w bajtach
    $
    """,
    re.VERBOSE,
)

# Wzorzec 2: Ścisła walidacja oktetów adresu IPv4 (0-255) z grupą nazwaną
IPV4_STRICT_RE: re.Pattern[str] = re.compile(
    r"""
    ^
    (?P<first_octet>25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)
    (?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}
    $
    """,
    re.VERBOSE,
)

# Wzorzec 3: Wykrywanie podejrzanych wzorców ataków w adresie URL
THREAT_PATTERN_RE: re.Pattern[str] = re.compile(
    r"(?P<threat>\.\./|union\s+select|<script|etc/passwd|/wp-admin)",
    re.IGNORECASE,
)