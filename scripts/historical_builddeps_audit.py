#!/usr/bin/env python3
"""Compare historical Launchpad ARM64 build dependencies to an Ubuntu 20.04 baseline.

Read-only. The baseline APT repositories deliberately do not include historical
PPA packages, so version differences are diagnostic, not build failures.
"""
import argparse
import hashlib
import json
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from build_evidence_audit import fetch_limited, paragraphs

URL = ("https://launchpad.net/~ondrej/+archive/ubuntu/php/+build/29118485/+files/"
       "php8.2_8.2.24-1+ubuntu20.04.1+deb.sury.org+1_arm64.buildinfo")
PINNED_HASH = "38951e3f62a8711a41ef739a3f9b827d3bed92c69a552ea6bc58d02e3f9d93ca"
VERSION = "8.2.24-1+ubuntu20.04.1+deb.sury.org+1"
# Critical native dependencies whose versions may differ in the PPA/Ubuntu snapshots.
WATCH_PREFIXES = (
    "libssl", "libicu", "libcurl", "libxml2", "libpcre2",
    "libzip", "libonig", "libsodium", "libargon2", "libgd",
    "libsqlite3", "libldap", "libpq", "libtidy", "libpng",
    "libjpeg", "libfreetype", "libedit", "libreadline",
    "libxslt", "libenchant", "libkrb5", "libmariadb", "libmysql",
    "libffi", "libc6", "libstdc++", "pkg-php-tools",
    "dh-php", "debhelper", "php-common",
)
PATTERN = re.compile(r"^\s*([a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?)\s*\(=\s*([^)]+)\)")


def list_builddeps(raw):
    items = []
    for line in raw.splitlines():
        piece = line.strip().rstrip(",")
        if not piece:
            continue
        match = PATTERN.match(piece)
        if match:
            items.append({"package": match.group(1), "historical_version": match.group(2).strip()})
    return items


def candidate(package):
    result = subprocess.run(["apt-cache", "policy", package], text=True,
                            capture_output=True, timeout=12, check=False)
    if result.returncode != 0:
        return None
    found = re.search(r"^\s*Candidate:\s*(\S+)", result.stdout, re.MULTILINE)
    return found.group(1) if found else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": "original Focal ARM64 Launchpad .buildinfo (2024-09-27)",
        "target_version": VERSION,
        "architecture": platform.machine(),
        "all_dependencies_count": 0,
        "selected_native_dependencies": [],
        "selected_matching_versions": 0,
        "selected_different_versions": 0,
        "historical_ppa_or_backport_dependencies": [],
        "unavailable_in_stock_focal": [],
        "reproducibility_gate": "BLOCKED_NO_ORIGINAL_PPA_SOURCE_OR_DEPENDENCY_SNAPSHOT",
        "warnings": [],
        "state": "INCOMPLETE",
        "build_performed": False,
        "production_modified": False,
    }
    try:
        if platform.machine() != "aarch64":
            raise RuntimeError("Expected native ARM64")
        os_text = Path("/etc/os-release").read_text()
        if 'VERSION_ID="20.04"' not in os_text:
            raise RuntimeError("Expected disposable Ubuntu 20.04 container")
        blob, _ = fetch_limited(URL, 1024 * 1024)
        if hashlib.sha256(blob).hexdigest() != PINNED_HASH:
            raise RuntimeError("Launchpad buildinfo SHA256 does not match pinned value")
        fields = paragraphs(blob.decode("utf-8"))
        if fields.get("Version") != VERSION:
            raise RuntimeError("Original buildinfo version mismatch")
        if fields.get("Architecture") != "arm64" or fields.get("Build-Architecture") != "arm64":
            raise RuntimeError("Original buildinfo architecture mismatch")
        values = fields.get("Installed-Build-Depends", "")
        depends = list_builddeps(values)
        if len(depends) < 50:
            raise RuntimeError("Historic Installed-Build-Depends missing or unexpectedly small")
        report["all_dependencies_count"] = len(depends)
        for entry in depends:
            pkg = entry["package"]
            name = pkg.split(":")[0]
            if not name.startswith(WATCH_PREFIXES):
                continue
            current = candidate(name)
            report["selected_native_dependencies"].append({
                "package": pkg,
                "historical_version": entry["historical_version"],
                "focal_current_candidate_without_ppa": current,
                "versions_identical": current == entry["historical_version"],
            })
        if not report["selected_native_dependencies"]:
            raise RuntimeError("No matching ABI-sensitive build dependencies")
        report["selected_matching_versions"] = sum(
            1 for item in report["selected_native_dependencies"] if item["versions_identical"]
        )
        report["selected_different_versions"] = (
            len(report["selected_native_dependencies"]) - report["selected_matching_versions"]
        )
        report["historical_ppa_or_backport_dependencies"] = [
            item["package"] for item in report["selected_native_dependencies"]
            if "deb.sury.org" in item["historical_version"]
            or "bpo20.04" in item["historical_version"]
        ]
        report["unavailable_in_stock_focal"] = [
            item["package"] for item in report["selected_native_dependencies"]
            if item["focal_current_candidate_without_ppa"] in (None, "(none)")
        ]

        report["state"] = "HISTORICAL_BUILD_DEPENDENCIES_AUDITED_NO_BUILD"
        report["warnings"].append(
            "Current APT candidate versions cannot recreate the 2024 dependency snapshot. "
            "Different versions are not proof of ABI incompatibility. "
            "This report does not verify exact PPA packaging or permit deployment."
        )
    except Exception as error:
        report["warnings"].append(str(error))
    finally:
        filename = Path(args.output)
        filename.parent.mkdir(parents=True, exist_ok=True)
        filename.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print("DEPENDENCY_AUDIT=" + report["state"])
        print("HISTORICAL_BUILD_DEPS=" + str(report["all_dependencies_count"]))
        print("ABI_SENSITIVE_DEPS=" + str(len(report["selected_native_dependencies"])))
        print("PRODUCTION_MODIFIED=False")
    return 0 if report["state"] == "HISTORICAL_BUILD_DEPENDENCIES_AUDITED_NO_BUILD" else 1


if __name__ == "__main__":
    raise SystemExit(main())
