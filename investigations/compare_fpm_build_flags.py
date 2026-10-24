#!/usr/bin/env python3
"""Read-only FPM configure-flag differential versus original Debian PHP packaging.

Source 1: exact pinned Launchpad 2024 ARM64 gzip build log.
Source 2: historic Debian PHP Team debian/rules pinned by SHA256.
This does not establish equivalence to the missing Ubuntu Focal PPA debian.tar.xz.
"""
import argparse
import gzip
import hashlib
import io
import json
import platform
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BUILD_LOG_URL = (
    "https://launchpad.net/~ondrej/+archive/ubuntu/php/+build/29118485/+files/"
    "buildlog_ubuntu-focal-arm64.php8.2_8.2.24-1+ubuntu20.04.1+deb.sury.org+1_BUILDING.txt.gz"
)
BUILD_LOG_SHA256 = "c8f1cee79a5d30d2c5954f1adaeee05989745c5b3dcd9ba89a9f9db99159511f"
DEBIAN_RULES_URL = (
    "https://salsa.debian.org/api/v4/projects/php-team%2Fphp/repository/files/"
    "debian%2Frules/raw?ref=debian%2F8.2.24-1_deb12u1"
)
DEBIAN_RULES_SHA256 = "ecac872e30c09ef6bf79853da5d1a2224f00c8f75c7968c6a9ee6bcf43897cab"
HOSTS = {"launchpad.net", "launchpadlibrarian.net", "salsa.debian.org"}
FLAGS = re.compile(r"--(?:enable|disable|with|without)-[A-Za-z0-9_.+-]+(?:=[A-Za-z0-9_./$:+{}-]+)?")
TARGET = re.compile(r"\bcd\s+([a-z0-9_+-]+-build)\s+&&\s+\.\./configure\s+")
IMPORTANT = (
    "--enable-fpm", "--enable-cli", "--disable-cgi",
    "--with-config-file-path=", "--with-config-file-scan-dir=",
    "--with-pdo-mysql", "--with-mysqli", "--enable-mbstring",
    "--with-openssl", "--with-curl", "--with-zip",
    "--enable-opcache", "--with-apxs2",
)


def get_verified(url, expected, size_limit):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in HOSTS:
        raise RuntimeError("Source host not allowed")
    req = urllib.request.Request(url, headers={"User-Agent": "php-security-builds-flag-audit/1.0"})
    with urllib.request.urlopen(req, timeout=35) as response:
        u = urllib.parse.urlsplit(response.geturl())
        if u.scheme != "https" or u.hostname not in HOSTS:
            raise RuntimeError("Unsafe redirect")
        raw = response.read(size_limit + 1)
        if len(raw) > size_limit:
            raise RuntimeError("Source exceeds size limit")
    if hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError("Pinned SHA256 mismatch")
    return raw


def scan_log(raw):
    commands = {}
    read_bytes = 0
    lines = 0
    truncated = False
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as opened:
        for original in opened:
            read_bytes += len(original)
            lines += 1
            if read_bytes > 100 * 1024 * 1024 or lines > 1_000_000:
                truncated = True
                break
            line = original.decode("utf-8", "replace").strip()
            matched = TARGET.search(line)
            if matched is None:
                continue
            target = matched.group(1)
            # Save only exact command line fingerprints and parsed flag evidence.
            if target not in commands:
                options = set(FLAGS.findall(line))
                commands[target] = {
                    "original_command_line_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
                    "full_line_bytes": len(line.encode("utf-8")),
                    "flag_count": len(options),
                    "important_flags": sorted(flag for flag in options if flag.startswith(IMPORTANT)),
                    "all_flags": sorted(options),
                }
    return {"lines": lines, "expanded_bytes": read_bytes,
            "complete": not truncated, "targets": commands}


def extract_rules_flags(blob):
    text = blob.decode("utf-8", "strict")
    # Debian rules has variable substitution; these flags are only lexical.
    config_lines = [
        line.strip() for line in text.splitlines()
        if "_config" in line or "--enable-fpm" in line or "--with-config-file-path=" in line
    ]
    flags = sorted(set(FLAGS.findall(text)))
    return {
        "rules_total_lines": len(text.splitlines()),
        "config_related_lines": len(config_lines),
        "lexical_flags": flags,
        "note": "Lexical flags are not fully expanded debian/rules variables.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    out = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "architecture": platform.machine(), "state": "INCOMPLETE",
        "source_exact_focal_ppa_packaging_recovered": False,
        "source_verified_original_arm64_buildlog": False,
        "debian_rules_verified": False,
        "original_build": None, "historical_debian_rules": None,
        "debian_ppa_byte_identical": None,
        "candidate_flags_missing_in_historical_debian_rules": [],
        "production_modified": False, "packages_built": False,
        "errors": [],
    }
    try:
        if platform.machine() != "aarch64":
            raise RuntimeError("ARM64 runner required")
        original = get_verified(BUILD_LOG_URL, BUILD_LOG_SHA256, 4 * 1024 * 1024)
        out["source_verified_original_arm64_buildlog"] = True
        historic = scan_log(original)
        if not historic["complete"] or not historic["targets"]:
            raise RuntimeError("No complete configure command evidence in original build log")
        out["original_build"] = historic
        rules = get_verified(DEBIAN_RULES_URL, DEBIAN_RULES_SHA256, 64 * 1024)
        out["debian_rules_verified"] = True
        out["historical_debian_rules"] = extract_rules_flags(rules)
        original_flags = set()
        for cmd in historic["targets"].values():
            original_flags.update(cmd["all_flags"])
        rule_flags = set(out["historical_debian_rules"]["lexical_flags"])
        out["candidate_flags_missing_in_historical_debian_rules"] = sorted(
            x for x in original_flags - rule_flags
            if x.startswith(("--with-", "--enable-")) and len(x) < 120
        )[:160]
        out["state"] = "PINNED_FOCAL_BUILD_FLAGS_AND_DEBIAN_RULES_COMPARED"
    except Exception as error:
        out["errors"].append(str(error))
    finally:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(out, sort_keys=True, indent=2, ensure_ascii=False) + "\n")
        print("FPM_FLAG_AUDIT=" + out["state"])
        print("ORIGINAL_BUILD_TARGETS=" + ",".join(sorted((out["original_build"] or {}).get("targets", {}))))
        print("EXACT_FOCAL_PACKAGING_PROVEN=False")
        print("PRODUCTION_MODIFIED=False")
    return 0 if out["state"] == "PINNED_FOCAL_BUILD_FLAGS_AND_DEBIAN_RULES_COMPARED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
