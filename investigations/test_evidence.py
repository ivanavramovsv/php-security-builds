"""Offline regression tests for provenance parsing. No network required."""
import gzip
import importlib.util
import pathlib
import unittest

FOLDER = pathlib.Path(__file__).parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, FOLDER / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rollback = load("focal_build_and_rollback", "focal_build_and_rollback.py")
flags = load("compare_fpm_build_flags", "compare_fpm_build_flags.py")


class ArchiveEvidenceTests(unittest.TestCase):
    def test_deb822_checksum_continuations(self):
        data = """Format: 1.8
Version: 8.2.24-1+ubuntu20.04.1+deb.sury.org+1
Checksums-Sha256:
 abcd 3 file.deb
 ffff 7 other.deb
"""
        fields = rollback.deb822_fields(data)
        self.assertEqual(fields["Version"], rollback.VERSION)
        manifest = rollback.checksum_entries(fields)
        self.assertEqual(manifest, {})

    def test_valid_checksum_manifest(self):
        manifest = "Checksums-Sha256:\n " + "a" * 64 + " 123 php8.2-fpm.deb\n"
        items = rollback.checksum_entries(rollback.deb822_fields(manifest))
        self.assertEqual(items["php8.2-fpm.deb"]["bytes"], 123)
        self.assertEqual(items["php8.2-fpm.deb"]["sha256"], "a" * 64)

    def test_build_target_extraction(self):
        line = "cd fpm-build && ../configure --enable-fpm --enable-mbstring=shared --with-config-file-path=/etc/php/8.2/fpm"
        compressed = gzip.compress((line + "\n").encode())
        result = flags.scan_log(compressed)
        self.assertTrue(result["complete"])
        self.assertIn("fpm-build", result["targets"])
        options = result["targets"]["fpm-build"]["all_flags"]
        self.assertIn("--enable-fpm", options)
        self.assertIn("--with-config-file-path=/etc/php/8.2/fpm", options)

    def test_rollback_target_versions_pinned(self):
        self.assertIn("ubuntu20.04", rollback.VERSION)
        self.assertEqual(rollback.BUILD_ID, "29118485")
        self.assertFalse(rollback.probe_rollback("not-in-manifest.deb", {})["verified"])


if __name__ == "__main__":
    unittest.main()
