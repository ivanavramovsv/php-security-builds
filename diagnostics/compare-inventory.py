#!/usr/bin/env python3
"""Parse a deliberately low-disclosure PHP inventory; never grant deployment approval.

No runtime dependencies. Safe for local/offline use, no network and no files
created. The report itself must NEVER be committed to public GitHub.
"""
import argparse
import re
import sys

FAMILIES = ("7.4", "8.0", "8.2")
EXPECTED_INSTALLED = {"7.4": "7.4.33", "8.0": "8.0.30", "8.2": "8.2.24"}
EXPECTED_API = {"7.4": "20190902", "8.0": "20200930", "8.2": "20220829"}


def parse(text):
    result = {"global": {}, "families": {v: {"extensions": {}, "packages": {}} for v in FAMILIES}}
    current = None
    for line in text.splitlines():
        m = re.fullmatch(r"===== PHP_(7[.]4|8[.]0|8[.]2) =====", line)
        if m:
            current = m.group(1)
            continue
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        if current is None:
            result["global"][key] = value
            continue
        family = result["families"][current]
        if key == "CLI_EXTENSION" and "|VERSION=" in value:
            name, version = value.split("|VERSION=", 1)
            family["extensions"][name.lower()] = version
        elif key == "INSTALLED_PACKAGE" and "|VERSION=" in value:
            name, version = value.split("|VERSION=", 1)
            family["packages"][name] = version
        else:
            family[key] = value
    # REPORT_END appears after final PHP block.
    if "REPORT_END" in result["families"]["8.2"]:
        result["global"]["REPORT_END"] = result["families"]["8.2"].pop("REPORT_END")
    if "DPKG_AUDIT" in result["families"]["8.2"]:
        result["global"]["DPKG_AUDIT"] = result["families"]["8.2"].pop("DPKG_AUDIT")
    return result


def analyze(text):
    report = parse(text)
    global_data = report["global"]
    findings = []
    if global_data.get("REPORT") != "PHP_ARM64_COMPATIBILITY_INVENTORY_V1":
        findings.append("REPORT_FORMAT=INVALID_OR_UNKNOWN")
    else:
        findings.append("REPORT_FORMAT=PASS")
    findings.append("REPORT_COMPLETE=" + (
        "PASS" if global_data.get("REPORT_END") == "YES" else "UNKNOWN"
    ))
    findings.append("ARCHITECTURE=" + (
        "PASS" if global_data.get("ARCH") == "aarch64" else "REVIEW"
    ))
    findings.append("OS_FOCAL=" + (
        "PASS" if global_data.get("OS_ID") == "ubuntu"
        and global_data.get("OS_VERSION") == "20.04" else "REVIEW"
    ))
    findings.append("DPKG_AUDIT=" + global_data.get("DPKG_AUDIT", "UNKNOWN"))
    for v in FAMILIES:
        family = report["families"][v]
        key = "PHP_" + v.replace(".", "_")
        installed = family.get("CLI_VERSION", "UNKNOWN")
        findings.append(key + "_CLI_VERSION=" + installed)
        findings.append(key + "_BASELINE_VERSION=" + (
            "MATCH" if installed == EXPECTED_INSTALLED[v] else "REVIEW"
        ))
        findings.append(key + "_NTS=" + (
            "PASS" if family.get("CLI_PHP_ZTS") == "0" else "REVIEW"
        ))
        suffix = family.get("EXTENSION_DIR_API_SUFFIX", "")
        api = family.get("PHPIZE_API", "")
        api_match = (
            api == EXPECTED_API[v] or
            (api == "NOT_INSTALLED" and suffix.endswith(EXPECTED_API[v]))
        )
        findings.append(key + "_EXPECTED_API=" + EXPECTED_API[v])
        findings.append(key + "_API_EVIDENCE=" + ("MATCH" if api_match else "REVIEW"))
        findings.append(key + "_FPM_SERVICE=" + family.get("FPM_SERVICE_STATE", "UNKNOWN"))
        mitigation = family.get("FPM_UPLOAD_PROGRESS_MITIGATION_FILE", "UNKNOWN")
        findings.append(key + "_MITIGATION_FILE_VALUE=" + mitigation)
        if v == "8.2":
            cli_imagick = family["extensions"].get("imagick", "NOT_LOADED")
            fpm_names = set(x.strip().lower() for x in
                            family.get("FPM_MODULE_NAMES", "").split(",") if x.strip())
            findings.append("PHP_8_2_INSTALLED_IMAGICK_VERSION=" + cli_imagick)
            findings.append("PHP_8_2_FPM_IMAGICK=" + (
                "YES" if "imagick" in fpm_names else "NOT_OBSERVED"
            ))
            findings.append("PHP_8_2_OLD_IMAGICK_SHA256=" +
                            family.get("IMAGICK_SO_SHA256", "NOT_AVAILABLE"))
            findings.append("PHP_8_2_OLD_IMAGICK_DEPENDENCIES=" +
                            family.get("IMAGICK_SO_NEEDED_LIBRARIES", "NOT_AVAILABLE"))
    findings.append("PHP_8_2_ISOLATED_SMOKE_TARGET=8.2.35")
    findings.append("PHP_8_2_ISOLATED_IMAGICK_SMOKE=3.8.1")
    findings.append("ORIGINAL_FOCAL_PPA_PACKAGING_RECOVERED=NO")
    findings.append("VERIFIED_ORIGINAL_DEB_ROLLBACK_AVAILABLE=NO")
    findings.append("PRODUCTION_DEPLOYMENT_READY=NO")
    return findings


def main():
    p = argparse.ArgumentParser()
    p.add_argument("report", nargs="?", help="Output of the read-only shell inventory; defaults to stdin")
    args = p.parse_args()
    if args.report:
        with open(args.report, encoding="utf-8") as f:
            data = f.read(262144)
    else:
        data = sys.stdin.read(262144)
    for line in analyze(data):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
