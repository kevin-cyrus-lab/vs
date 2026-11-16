import unittest
import tempfile
from pathlib import Path
from vibesecurity.core.models import Finding, RiskLevel, Severity
from vibesecurity.remediation.patch_generator import PatchGenerator
from vibesecurity.remediation.patch_validator import PatchValidator
from vibesecurity.remediation.patch_applier import PatchApplier
from vibesecurity.remediation.rollback import PatchRollbackManager

class TestRemediation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_env_gitignore_patch_and_rollback(self):
        gitignore = self.root / ".gitignore"
        gitignore.write_text("node_modules\n", encoding="utf-8")

        finding = Finding(
            id="VS-TEST-01",
            title=".env not ignored",
            severity=Severity.HIGH.value,
            category="infrastructure",
            cwe="CWE-552",
            file_path=".gitignore",
            line_start=1,
            line_end=1,
            code_snippet=".env",
            rule_id="env-file-not-ignored",
            scanner="infrastructure_scanner",
            remediation_strategy="add-to-gitignore",
            risk_level=RiskLevel.LOW.value
        )

        gen = PatchGenerator(self.root)
        patch = gen.generate_patch(finding)
        self.assertIsNotNone(patch)
        self.assertIn(".env", patch.patched_snippet)

        val = PatchValidator(self.root)
        is_valid, msg = val.validate(patch)
        self.assertTrue(is_valid)

        applier = PatchApplier(self.root)
        applied, app_msg = applier.apply(patch)
        self.assertTrue(applied)
        self.assertIn(".env", gitignore.read_text(encoding="utf-8"))

        # Test Rollback
        rollback_mgr = PatchRollbackManager(self.root)
        rolled, roll_msg = rollback_mgr.rollback(patch)
        self.assertTrue(rolled)
        self.assertEqual(gitignore.read_text(encoding="utf-8"), "node_modules\n")

if __name__ == "__main__":
    unittest.main()

