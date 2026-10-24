#!/usr/bin/env python3
"""Find exact original PHP Focal source files using SHA-256 from Launchpad.

This is a discovery-only, non-executing audit. It never compiles or deploys.
Never trust a filename or a mirror listing without matching exact checksums.
"""
import argparse
import hashlib
import json
import platform
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from build_evidence_audit import paragraphs, sha_entries, fetch_limited

SOURCE_CHANGE_URL = (
    "https://launchpad.net/~ondrej/+archive/ubuntu/php/+files/"
    "php8.2_8.2.24-1+ubuntu20.04.1+deb.sury.org+1_source.changes"
)
SOURCE_CHANGES_SHA256 = "0fff290f95f22f20191bc799b2f62157b434fb8aea3ddbea51bacfd863da1213"
VERSION = "8.2.24-1+ubuntu20.04.1+deb.sury.org+1"
TARGETS = {
    "php8.2_" + VERSION + ".dsc":
        "310a71132026af4299bd7ef9e85cef19aa421bb2a78103934ba23dc3b636fd9f",
    "php8.2_" + VERSION + ".debian.tar.xz":
        "e1d4f7d158176d9c4d78a425220caf024902136e1f3a3bc18c5057e12aa2853e",
    "php8.2_8.2.24.orig.tar.xz":
        "80a5225746a9eb484475b312d4c626c63a88a037d8e56d214f30205e1ba1411a",
}
PUBLIC_BASES = (
    "https://launchpad.net/~ondrej/+archive/ubuntu/php/+files/",
    "https://ppa.launchpadcontent.net/ondrej/php/ubuntu/pool/main/p/php8.2/",
)
ALLOWED = {"launchpad.net", "launchpadlibrarian.net", "ppa.launchpadcontent.net"}


def download_verified(url, maxsize):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED:
        raise ValueError("unapproved repository host")
    req = urllib.request.Request(url, headers={"User-Agent": "php-security-builds-historical-source-check/1.0"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        redirected = urllib.parse.urlparse(resp.geturl())
        if redirected.scheme != "https" or redirected.hostname not in ALLOWED:
            raise ValueError("unapproved redirect")
        result = resp.read(maxsize + 1)
        if len(result) > maxsize:
            raise ValueError("download exceeds size cap")
        return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    report = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "architecture": platform.machine(),
        "exact_ubuntu_ppa_version": VERSION,
        "files": {},
        "source_changes_pinned_hash_matched": False,
        "original_source_recovered": False,
        "build_performed": False,
        "production_modified": False,
        "state": "NO_EXACT_SOURCE_ARCHIVES_VERIFIED",
        "errors": [],
    }
    try:
        if platform.machine() != "aarch64":
            raise ValueError("ARM64 runner required")
        changes, _ = fetch_limited(SOURCE_CHANGE_URL, 1024 * 1024)
        if hashlib.sha256(changes).hexdigest() != SOURCE_CHANGES_SHA256:
            raise ValueError("Launchpad source changes digest differs from pinned value")
        report["source_changes_pinned_hash_matched"] = True
        fields = paragraphs(changes.decode("utf-8"))
        if fields.get("Version") != VERSION or fields.get("Architecture") != "source":
            raise ValueError("Source changes has wrong version or architecture")
        checks = {entry["filename"]: entry for entry in sha_entries(fields.get("Checksums-Sha256", ""))}
        for name, expected_sha in TARGETS.items():
            entry = checks.get(name)
            if not entry or entry["sha256"] != expected_sha:
                raise ValueError("Source changes lacks pinned checksum: " + name)
        for name, expected_sha in TARGETS.items():
            target = checks[name]
            entry = {
                "filename": name, "expected_sha256": expected_sha,
                "expected_bytes": target["bytes"],
                "sha256_verified": False,
                "attempts": [],
            }
            report["files"][name] = entry
            for base in PUBLIC_BASES:
                url = base + urllib.parse.quote(name, safe="+._-")
                attempt = {"host": urllib.parse.urlparse(url).hostname, "verified": False}
                entry["attempts"].append(attempt)
                try:
                    blob = download_verified(url, target["bytes"] + 1)
                    digest = hashlib.sha256(blob).hexdigest()
                    attempt["downloaded_bytes"] = len(blob)
                    attempt["sha256_match"] = digest == expected_sha
                    attempt["verified"] = len(blob) == target["bytes"] and digest == expected_sha
                    if attempt["verified"]:
                        entry["sha256_verified"] = True
                        break
                except urllib.error.HTTPError as exc:
                    attempt["http_status"] = exc.code
                except Exception as exc:
                    attempt["error"] = str(exc)[:180]
        report["original_source_recovered"] = all(v["sha256_verified"] for v in report["files"].values())
        if report["original_source_recovered"]:
            report["state"] = "EXACT_FILES_HASH_VERIFIED_IN_EPHEMERAL_RUNNER"
    except Exception as exc:
        report["errors"].append(str(exc)[:220])
        report["state"] = "INCOMPLETE"
    finally:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        print("SOURCE_RECOVERY=" + report["state"])
        for name, file in report["files"].items():
            print(name + "=" + ("SHA256_PASS" if file["sha256_verified"] else "NOT_VERIFIED"))
        print("PRODUCTION_MODIFIED=False")
    return 0 if report["state"] != "INCOMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
