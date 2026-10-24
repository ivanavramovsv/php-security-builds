#!/usr/bin/env python3
"""Read-only forensic download of exact 2024 PHP 8.2.24 Focal ARM64 build metadata.

This is NOT a source or binary release gate. Output only hashes, reachability
and selected metadata; it never executes archives or uploads server data.
"""
import argparse
import gzip
import hashlib
import json
import platform
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API_BUILD = "https://api.launchpad.net/devel/~ondrej/+archive/ubuntu/php/+build/29118485"
API_SOURCE = "https://api.launchpad.net/devel/~ondrej/+archive/ubuntu/php/+sourcepub/16505170"
VERSION = "8.2.24-1+ubuntu20.04.1+deb.sury.org+1"
ALLOWED_HOSTS = {"launchpad.net", "launchpadlibrarian.net", "api.launchpad.net"}
LIMITS = {"source_changes": 1024 * 1024,
          "arm64_changes": 1024 * 1024,
          "arm64_buildinfo": 4 * 1024 * 1024,
          "arm64_build_log": 12 * 1024 * 1024}
FIELDS = ("Format", "Source", "Binary", "Architecture", "Version",
          "Build-Architecture", "Build-Origin", "Build-Date",
          "Build-Path", "Build-Tainted-By", "Checksums-Sha256")


def allowed(url):
    p = urllib.parse.urlparse(url)
    return p.scheme == "https" and p.hostname in ALLOWED_HOSTS and not p.username and not p.password


def fetch_json(url):
    if not allowed(url):
        raise ValueError("unexpected API host")
    request = urllib.request.Request(url, headers={"User-Agent": "php-security-builds-evidence/1.0"})
    with urllib.request.urlopen(request, timeout=35) as resp:
        return json.load(resp)


def fetch_limited(url, limit):
    if not allowed(url):
        raise ValueError("untrusted metadata URL")
    req = urllib.request.Request(url, headers={"User-Agent": "php-security-builds-evidence/1.0"})
    with urllib.request.urlopen(req, timeout=40) as resp:
        final = resp.geturl()
        if not allowed(final):
            raise ValueError("redirect to unapproved host")
        blob = resp.read(limit + 1)
        if len(blob) > limit:
            raise ValueError("metadata exceeds size limit")
        return blob, final


def paragraphs(text):
    result = {}
    last = None
    for line in text.splitlines():
        if re.match(r"^[A-Za-z][A-Za-z0-9-]*:\s", line):
            name, value = line.split(":", 1)
            last = name
            result[name] = value.strip()
        elif line.startswith(" ") and last:
            result[last] += "\n" + line
        else:
            last = None
    return result


def sha_entries(value):
    entries = []
    for line in value.splitlines():
        parts = line.split()
        if len(parts) == 3 and re.fullmatch(r"[0-9a-f]{64}", parts[0]) and parts[1].isdigit():
            entries.append({"sha256": parts[0], "bytes": int(parts[1]), "filename": parts[2]})
    return entries[:100]


def extract_build_log(blob):
    if blob.startswith(b"\x1f\x8b"):
        text = gzip.decompress(blob).decode("utf-8", errors="replace")
    else:
        text = blob.decode("utf-8", errors="replace")
    lines = text.splitlines()
    # Reduce output size and avoid exposing environment variables in full logs.
    hits = [
        line.strip()[:250]
        for line in lines
        if re.search(r"(^|[\s/])(?:dpkg-buildpackage|debian/rules|dh_auto_configure)(?:[\s:]|$)", line)
    ]
    return {"decompressed_length": len(text), "line_count": len(lines),
            "build_command_sample": hits[:8]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    report = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "target_version": VERSION, "target_arch": "arm64", "files": {},
        "errors": [], "production_modified": False, "build_performed": False,
        "exact_source_archives_verified": False, "state": "INCOMPLETE",
    }
    try:
        if platform.machine() != "aarch64":
            raise ValueError("ARM64 required")
        build = fetch_json(API_BUILD)
        if (build.get("source_package_version") != VERSION or
                build.get("arch_tag") != "arm64" or
                build.get("buildstate") != "Successfully built"):
            raise ValueError("Launchpad build does not match exact version, architecture and state")
        source = fetch_json(API_SOURCE)
        if source.get("source_package_version") != VERSION:
            raise ValueError("Source publication version mismatch")
        control = {
            "source_changes": API_SOURCE + "?ws.op=changesFileUrl",
        }
        source_change_url = fetch_json(control["source_changes"])
        urls = {
            "source_changes": source_change_url,
            "arm64_changes": build.get("changesfile_url"),
            "arm64_buildinfo": build.get("buildinfo_url"),
            "arm64_build_log": build.get("build_log_url"),
        }
        for kind, url in urls.items():
            entry = {"available": False, "url": url if allowed(url) else None}
            report["files"][kind] = entry
            if not url:
                entry["error"] = "metadata has no URL"
                continue
            try:
                blob, final = fetch_limited(url, LIMITS[kind])
                entry["available"] = True
                entry["bytes"] = len(blob)
                entry["sha256"] = hashlib.sha256(blob).hexdigest()
                entry["resolved_host"] = urllib.parse.urlparse(final).hostname
                if kind == "arm64_build_log":
                    entry["log_summary"] = extract_build_log(blob)
                else:
                    info = paragraphs(blob.decode("utf-8", errors="replace"))
                    entry["pgp_signed"] = blob.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----")
                    entry["fields"] = {
                        k: info.get(k, "")[:300]
                        for k in FIELDS if k in info and k != "Checksums-Sha256"
                    }
                    entry["checksum_entries"] = sha_entries(info.get("Checksums-Sha256", ""))
                    # No signature verification in this stage.
                    entry["signature_verified"] = False
            except Exception as exc:
                entry["error"] = str(exc)[:250]
        report["state"] = "METADATA_INSPECTED_NOT_SOURCE_VERIFIED"
    except Exception as exc:
        report["errors"].append(str(exc)[:300])
    finally:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        print("EXACT_ARM64_BUILD_EVIDENCE=" + report["state"])
        for k, v in report["files"].items():
            print(k.upper() + "=" + ("AVAILABLE" if v["available"] else "UNAVAILABLE"))
        print("VERIFIED_SOURCE_ARCHIVES=False")
    return 0 if report["state"] == "METADATA_INSPECTED_NOT_SOURCE_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
