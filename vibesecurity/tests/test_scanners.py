import unittest
import tempfile
from pathlib import Path
from vibesecurity.engines.static_analyzer import StaticAnalysisScanner
from vibesecurity.engines.secrets_scanner import SecretsScanner
from vibesecurity.engines.infrastructure_scanner import InfrastructureScanner

class TestSecurityScanners(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sql_injection_detection(self):
        vulnerable_py = self.root / "app.py"
        vulnerable_py.write_text("""
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
""", encoding="utf-8")

        scanner = StaticAnalysisScanner(self.root)
        findings = scanner.scan()
        self.assertTrue(any(f.cwe == "CWE-89" for f in findings))

    def test_command_injection_detection(self):
        vulnerable_py = self.root / "exec.py"
        vulnerable_py.write_text("""
import os
def run_command(cmd):
    os.system("echo " + cmd)
""", encoding="utf-8")

        scanner = StaticAnalysisScanner(self.root)
        findings = scanner.scan()
        self.assertTrue(any(f.cwe == "CWE-78" for f in findings))

    def test_secrets_detection_and_redaction(self):
        sec_file = self.root / "config.js"
        sec_file.write_text("""
const apiKey = "sk-live_1234567890abcdef1234567890";
const openaiKey = "sk-abcdefghijklmnopqrstuvwxyz1234567890123456";
""", encoding="utf-8")

        scanner = SecretsScanner(self.root)
        findings = scanner.scan()
        self.assertTrue(len(findings) >= 1)
        for f in findings:
            self.assertNotIn("sk-live_1234567890abcdef", f.code_snippet)
            self.assertIn("REDACTED", f.code_snippet)

    def test_dockerfile_root_detection(self):
        df = self.root / "Dockerfile"
        df.write_text("""
FROM alpine:3.18
RUN echo hello
USER root
""", encoding="utf-8")

        scanner = InfrastructureScanner(self.root)
        findings = scanner.scan()
        self.assertTrue(any("USER" in f.title or "Root" in f.title for f in findings))

if __name__ == "__main__":
    unittest.main()

