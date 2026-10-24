#!/usr/bin/env python3
"""Read-only historical Ubuntu 20.04 ARM64 PHP build and rollback evidence.

Reads exact pinned Launchpad build log, buildinfo and .changes from 2024.
Extracts bounded configure/packaging evidence, then probes exact old .deb
files against the SHA256 checksums in .changes. Never installs or executes
downloaded binaries. No production access or credentials.
"""
import argparse
import gzip
import hashlib
import io
import json
import platform
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION = "8.2.24-1+ubuntu20.04.1+deb.sury.org+1"
BUILD_ID = "29118485"
BASE = "https://launchpad.net/~ondrej/+archive/ubuntu/php/+build/" + BUILD_ID + "/+files/"
SAFE_HOSTS = {"launchpad.net", "launchpadlibrarian.net", "ppa.launchpadcontent.net"}
FILES = {
    "arm64_changes": (
        f"php8.2_{VERSION}_arm64.changes",
        "3a359a69f5fc406a140c858cc968734d73fc8e5f4b1689adc7c065c951b03b18",
        128 * 1024,
    ),
    "arm64_buildinfo": (
        f"php8.2_{VERSION}_arm64.buildinfo",
        "38951e3f62a8711a41ef739a3f9b827d3bed92c69a552ea6bc58d02e3f9d93ca",
        128 * 1024,
    ),
    "arm64_buildlog": (
        f"buildlog_ubuntu-focal-arm64.php8.2_{VERSION}_BUILDING.txt.gz",
        "c8f1cee79a5d30d2c5954f1adaeee05989745c5b3dcd9ba89a9f9db99159511f",
        4 * 1024 * 1024,
    ),
}
ROLLBACK_NAMES = (
    "php8.2-fpm", "php8.2-cli", "php8.2-common", "php8.2-opcache",
    "php8.2-mysql", "php8.2-mbstring", "php8.2-xml",
)
# The compressed original build log is 2.6 MB and expands to about 57 MB.
MAX_DECOMPRESSED = 100 * 1024 * 1024


def validate_url(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.hostname not in SAFE_HOSTS or u.username or u.password:
        raise ValueError("URL outside explicitly allowed Launchpad hosts")
    return url


def limited_download(url, limit, timeout=20):
    validate_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": "php-security-builds-forensic-probe/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as handle:
        validate_url(handle.geturl())
        if (handle.length is not None) and handle.length > limit:
            raise ValueError("remote payload larger than size limit")
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise ValueError("payload larger than size limit")
        return data


def get_original(kind):
    name, expected, limit = FILES[kind]
    blob = limited_download(BASE + urllib.parse.quote(name, safe="+._-"), limit)
    actual = hashlib.sha256(blob).hexdigest()
    if actual != expected:
        raise ValueError("original Launchpad " + kind + " checksum mismatch")
    return blob


def deb822_fields(content):
    fields = {}
    last = None
    for line in content.splitlines():
        m = re.match(r"^([A-Za-z][\w-]*):[ \t]*(.*)$", line)
        if m:
            last = m.group(1)
            fields[last] = m.group(2)
        elif line.startswith((" ", "\t")) and last:
            fields[last] += "\n" + line
        else:
            last = None
    return fields


def checksum_entries(fields):
    out = {}
    for line in fields.get("Checksums-Sha256", "").splitlines():
        items = line.split()
        if len(items) == 3 and re.fullmatch("[0-9a-f]{64}", items[0]) and items[1].isdigit():
            out[items[2]] = {"sha256": items[0], "bytes": int(items[1])}
    return out


def inspect_buildlog(compressed):
    configure_examples = []
    build_steps = []
    configure_tokens = set()
    expanded = 0
    total_lines = 0
    truncated = False
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        for raw in stream:
            expanded += len(raw)
            total_lines += 1
            if expanded > MAX_DECOMPRESSED or total_lines > 1_000_000:
                truncated = True
                break
            line = raw.decode("utf-8", "replace").strip()
            if ("./configure" in line or "configure --" in line) and len(configure_examples) < 20:
                configure_examples.append(line[:500])
            if ("debian/rules " in line or "dh_auto_configure" in line) and len(build_steps) < 18:
                build_steps.append(line[:500])
            if ("./configure" in line or line.startswith("--") or " --with-" in line):
                for token in re.findall(
                    r"--(?:enable|disable|with|without)-[a-zA-Z0-9_.+-]+(?:=[a-zA-Z0-9_./+-]+)?",
                    line,
                ):
                    if len(configure_tokens) < 250:
                        configure_tokens.add(token)
    return {
        "complete_scan": not truncated,
        "expanded_bytes_scanned": expanded,
        "lines_scanned": total_lines,
        "configure_line_samples": configure_examples,
        "configure_tokens_seen": sorted(configure_tokens),
        "build_command_samples": build_steps,
        "note": "Samples from the original public build log; not proof of complete effective configure flags.",
    }


def candidate_urls(filename):
    escaped = urllib.parse.quote(filename, safe="+._-")
    return [
        BASE + escaped,
        "https://ppa.launchpadcontent.net/ondrej/php/ubuntu/pool/main/p/php8.2/" + escaped,
    ]


def probe_rollback(filename, manifest):
    item = {
        "filename": filename,
        "manifest_present": filename in manifest,
        "verified": False,
        "available": False,
        "attempts": [],
    }
    if filename not in manifest:
        return item
    expected = manifest[filename]
    item["expected_sha256"] = expected["sha256"]
    item["expected_size"] = expected["bytes"]
    if expected["bytes"] > 15 * 1024 * 1024:
        item["attempts"].append({"error": "Binary larger than 15 MiB safety cap"})
        return item
    for url in candidate_urls(filename):
        attempt = {"host": urllib.parse.urlsplit(url).hostname, "sha256_match": False}
        item["attempts"].append(attempt)
        try:
            # In-memory only, never written to disk or executed, never uploaded.
            data = limited_download(url, expected["bytes"] + 1, timeout=12)
            attempt["response_size"] = len(data)
            attempt["sha256_match"] = len(data) == expected["bytes"] and (
                hashlib.sha256(data).hexdigest() == expected["sha256"]
            )
            if attempt["sha256_match"]:
                item["verified"] = True
                item["available"] = True
                break
        except urllib.error.HTTPError as error:
            attempt["http_status"] = error.code
        except Exception as error:
            attempt["error"] = str(error)[:180]
    return item


def run(report_path):
    report = {
        "at_utc": datetime.now(timezone.utc).isoformat(),
        "historical_build": BUILD_ID,
        "source_version": VERSION,
        "architecture": platform.machine(),
        "historical_evidence_sha256_pinned": False,
        "build_log": None,
        "rollback_probes": [],
        "rollback_verified_count": 0,
        "total_rollback_probes": len(ROLLBACK_NAMES),
        "deployment_ready": False,
        "exact_ppa_source_recovered": False,
        "production_modified": False,
        "packages_built": False,
        "errors": [],
        "status": "BLOCKED",
    }
    try:
        if platform.machine() != "aarch64":
            raise RuntimeError("Expected native ARM64")
        changes = deb822_fields(get_original("arm64_changes").decode("utf-8", "replace"))
        buildinfo = deb822_fields(get_original("arm64_buildinfo").decode("utf-8", "replace"))
        if changes.get("Version") != VERSION or changes.get("Architecture") != "arm64":
            raise RuntimeError("Historical .changes source version/architecture mismatch")
        if buildinfo.get("Version") != VERSION or buildinfo.get("Build-Architecture") != "arm64":
            raise RuntimeError("Historical .buildinfo version/architecture mismatch")
        if not buildinfo.get("Installed-Build-Depends"):
            raise RuntimeError("Historical buildinfo lacks dependencies")
        log = get_original("arm64_buildlog")
        report["historical_evidence_sha256_pinned"] = True
        report["build_log"] = inspect_buildlog(log)
        if not report["build_log"]["complete_scan"]:
            raise RuntimeError("Original build log hit decompression scan cap")
        manifest = checksum_entries(changes)
        if not manifest:
            raise RuntimeError("No SHA256 manifest in original ARM64 .changes")
        for package in ROLLBACK_NAMES:
            filename = f"{package}_{VERSION}_arm64.deb"
            report["rollback_probes"].append(probe_rollback(filename, manifest))
        report["rollback_verified_count"] = sum(x["verified"] for x in report["rollback_probes"])
        report["status"] = "HISTORICAL_LOG_AND_ROLLBACK_PROBES_COMPLETE"
    except Exception as error:
        report["errors"].append(str(error)[:300])
    finally:
        path = Path(report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + "\n")
        print("HISTORY_AUDIT=" + report["status"])
        print("CONFIGURE_SAMPLES=" + str(len((report["build_log"] or {}).get("configure_line_samples", []))))
        print("ROLLBACK_VERIFIED=" + str(report["rollback_verified_count"]))
        print("DEPLOYMENT_READY=False")
    return 0 if report["status"] == "HISTORICAL_LOG_AND_ROLLBACK_PROBES_COMPLETE" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    raise SystemExit(run(parser.parse_args().output))
