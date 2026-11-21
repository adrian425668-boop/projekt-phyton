"""Testy jednostkowe weryfikujące wszystkie kluczowe mechanizmy projektu."""

from pathlib import Path
import tempfile
import unittest

from core.analyzer import analyze_file_multiprocess
from core.models import AnalysisConfig, LogReportSession
from core.patterns import IPV4_STRICT_RE, LOG_LINE_RE, THREAT_PATTERN_RE
from core.pipeline import filter_error_entries, parse_log_stream, stream_multiple_files
from core.reader import ChunkLogReader
from io_tasks.enricher import enrich_ips_multithreaded
from utils.decorators import retry


class TestAdvancedPythonProject(unittest.TestCase):
    """Zestaw testów jednostkowych dla analizatora logów."""

    def test_retry_decorator(self) -> None:
        attempts_made = 0

        @retry(attempts=3, delay=0.001, exceptions=(ValueError,))
        def flaky() -> str:
            nonlocal attempts_made
            attempts_made += 1
            if attempts_made < 3:
                raise ValueError("Błąd przejściowy")
            return "SUKCES"

        self.assertEqual(flaky(), "SUKCES")
        self.assertEqual(attempts_made, 3)

    def test_method_decorators_and_property(self) -> None:
        with self.assertRaises(ValueError):
            AnalysisConfig(min_status_code=999)

        cfg = AnalysisConfig.from_dict({"min_status_code": 404, "top_n": 2})
        self.assertTrue(AnalysisConfig.is_error_status(500))
        self.assertFalse(AnalysisConfig.is_error_status(200))

        session = LogReportSession(cfg)
        with self.assertRaises(RuntimeError):
            session.top_client_ips()

        session.load_entries([{"ip": "10.0.0.1", "threat": None}])
        self.assertEqual(session.top_client_ips(), [("10.0.0.1", 1)])

    def test_regex_patterns(self) -> None:
        sample = '83.14.201.4 - - [17/Nov/2026:12:00:00 +0100] "GET /../../etc/passwd HTTP/1.1" 403 128'
        match = LOG_LINE_RE.match(sample)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("ip"), "83.14.201.4")
        self.assertEqual(match.group("status"), "403")

        self.assertIsNotNone(IPV4_STRICT_RE.match("192.168.0.1"))
        self.assertIsNone(IPV4_STRICT_RE.match("999.168.0.1"))

        threat = THREAT_PATTERN_RE.search(match.group("url"))
        self.assertIsNotNone(threat)

    def test_iterator_and_generators(self) -> None:
        lines = [
            '10.0.0.1 - - [17/Nov/2026:10:00:00 +0100] "GET /ok HTTP/1.1" 200 100',
            '10.0.0.2 - - [17/Nov/2026:10:00:01 +0100] "POST /login HTTP/1.1" 401 64',
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            p1 = Path(tmpdir) / "a.log"
            p2 = Path(tmpdir) / "b.log"
            p1.write_text(lines[0] + "\n", encoding="utf-8")
            p2.write_text(lines[1] + "\n", encoding="utf-8")

            with ChunkLogReader(p1, chunk_size=1) as reader:
                self.assertEqual(list(reader), [[lines[0]]])

            combined = list(stream_multiple_files([p1, p2]))
            parsed = list(parse_log_stream(combined))
            errors = list(filter_error_entries(parsed, min_status=400))
            self.assertEqual(len(parsed), 2)
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0]["status"], 401)

    def test_multithreading_and_multiprocessing(self) -> None:
        enriched = enrich_ips_multithreaded(["10.0.0.5", "83.14.201.4"], max_workers=2)
        self.assertEqual(enriched["83.14.201.4"]["country"], "PL")

        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.log"
            log_file.write_text(
                '10.0.0.5 - - [17/Nov/2026:10:00:00 +0100] "GET / HTTP/1.1" 200 50\n' * 20,
                encoding="utf-8",
            )
            result = analyze_file_multiprocess(log_file, chunk_size=5, max_workers=2)
            self.assertEqual(result["total_valid"], 20)


if __name__ == "__main__":
    unittest.main()