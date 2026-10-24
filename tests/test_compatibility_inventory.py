"""Fast offline regression tests for safe Oracle PHP inventory diagnostics."""
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "compat_compare", ROOT / "diagnostics" / "compare-inventory.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

BASE = """REPORT=PHP_ARM64_COMPATIBILITY_INVENTORY_V1
MODE=READ_ONLY
PRODUCTION_WRITE_OPERATIONS=0
ARCH=aarch64
OS_ID=ubuntu
OS_VERSION=20.04
===== PHP_7.4 =====
CLI_VERSION=7.4.33
CLI_PHP_ZTS=0
PHPIZE_API=NOT_INSTALLED
EXTENSION_DIR_API_SUFFIX=20190902
FPM_SERVICE_STATE=active
FPM_UPLOAD_PROGRESS_MITIGATION_FILE=0
===== PHP_8.0 =====
CLI_VERSION=8.0.30
CLI_PHP_ZTS=0
PHPIZE_API=20200930
EXTENSION_DIR_API_SUFFIX=20200930
FPM_SERVICE_STATE=active
FPM_UPLOAD_PROGRESS_MITIGATION_FILE=0
===== PHP_8.2 =====
CLI_VERSION=8.2.24
CLI_PHP_ZTS=0
PHPIZE_API=NOT_INSTALLED
EXTENSION_DIR_API_SUFFIX=20220829
CLI_EXTENSION=imagick|VERSION=3.7.0
CLI_EXTENSION=openssl|VERSION=8.2.24
FPM_MODULE_NAMES=imagick,mysqli,mbstring,openssl
FPM_SERVICE_STATE=active
IMAGICK_SO_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
IMAGICK_SO_NEEDED_LIBRARIES=libMagickWand-6.Q16.so.6,libc.so.6
FPM_UPLOAD_PROGRESS_MITIGATION_FILE=0
DPKG_AUDIT=CLEAN
REPORT_END=YES
"""


class CompatTests(unittest.TestCase):
    def test_original_server_example(self):
        result = module.analyze(BASE)
        self.assertIn("REPORT_FORMAT=PASS", result)
        self.assertIn("REPORT_COMPLETE=PASS", result)
        self.assertIn("ARCHITECTURE=PASS", result)
        self.assertIn("OS_FOCAL=PASS", result)
        for v in ("7_4", "8_0", "8_2"):
            self.assertIn("PHP_" + v + "_API_EVIDENCE=MATCH", result)
            self.assertIn("PHP_" + v + "_BASELINE_VERSION=MATCH", result)
        self.assertIn("PHP_8_2_INSTALLED_IMAGICK_VERSION=3.7.0", result)
        self.assertIn("PHP_8_2_FPM_IMAGICK=YES", result)
        self.assertIn("PRODUCTION_DEPLOYMENT_READY=NO", result)

    def test_missing_critical_info_must_not_pass(self):
        result = module.analyze("MODE=READ_ONLY\n===== PHP_8.2 =====\nCLI_VERSION=8.2.35\n")
        self.assertIn("REPORT_FORMAT=INVALID_OR_UNKNOWN", result)
        self.assertIn("REPORT_COMPLETE=UNKNOWN", result)
        self.assertIn("PHP_8_2_BASELINE_VERSION=REVIEW", result)
        self.assertIn("PHP_8_2_API_EVIDENCE=REVIEW", result)
        self.assertIn("PRODUCTION_DEPLOYMENT_READY=NO", result)

    def test_module_list_does_not_treat_imagick_like_as_imagick(self):
        modified = BASE.replace(
            "FPM_MODULE_NAMES=imagick,mysqli,mbstring,openssl",
            "FPM_MODULE_NAMES=imagick_custom,mysqli,mbstring,openssl",
        )
        self.assertIn("PHP_8_2_FPM_IMAGICK=NOT_OBSERVED", module.analyze(modified))

    def test_successful_inventory_still_cannot_approve_deployment(self):
        report = BASE.replace(
            "CLI_VERSION=8.2.24", "CLI_VERSION=8.2.35"
        ).replace("IMAGICK_SO_NEEDED_LIBRARIES=", "IMAGICK_SO_NEEDED_LIBRARIES=")
        self.assertIn("PRODUCTION_DEPLOYMENT_READY=NO", module.analyze(report))


if __name__ == "__main__":
    unittest.main()
