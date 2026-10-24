#!/usr/bin/env python3
"""Read-only Launchpad publication forensics for exact historical Focal PHP source.

Gathers metadata, historical build identifiers and artifact URLs. No packages
are downloaded, compiled, installed or deployed. Treat empty responses as
absence of evidence, not proof that an archive never existed.
"""
import argparse
import json
import platform
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = "https://api.launchpad.net/devel/~ondrej/+archive/ubuntu/php/+sourcepub/16505170"
VERSION = "8.2.24-1+ubuntu20.04.1+deb.sury.org+1"
SOURCE = "php8.2"
USER_AGENT = "php-security-builds-launchpad-forensics/1.0"
MAX_URLS = 30


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=35) as response:
        return json.load(response)


def operation(name, **kwargs):
    params = {"ws.op": name}
    params.update(kwargs)
    return fetch_json(BASE + "?" + urllib.parse.urlencode(params))


def safe_url(value):
    if not isinstance(value, str):
        return None
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return None
    if parsed.hostname not in (
        "api.launchpad.net", "launchpadlibrarian.net",
        "launchpad.net", "ppa.launchpadcontent.net",
    ):
        return None
    return value[:2048]


def urls_from_payload(payload):
    if isinstance(payload, list):
        return [url for url in (safe_url(u) for u in payload) if url]
    if isinstance(payload, dict):
        return [
            url for url in (
                safe_url(entry.get("url") if isinstance(entry, dict) else entry)
                for entry in payload.get("entries", [])
            ) if url
        ]
    return [url for url in [safe_url(payload)] if url]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    args = p.parse_args()
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "query": {"source": SOURCE, "version": VERSION, "publication": BASE},
        "environment": {"architecture": platform.machine()},
        "publication": None,
        "source_file_urls": [],
        "source_file_urls_with_meta": [],
        "changes_file_url": None,
        "builds": [],
        "lookup_errors": [],
        "exact_source_files_verified": False,
        "build_performed": False,
        "production_modified": False,
        "result": "INCOMPLETE",
    }

    try:
        if platform.machine() != "aarch64":
            raise ValueError("ARM64 runner required")
        publication = fetch_json(BASE)
        if publication.get("source_package_name") != SOURCE:
            raise ValueError("Unexpected source name")
        if publication.get("source_package_version") != VERSION:
            raise ValueError("Unexpected source version")
        if not publication.get("distro_series_link", "").rstrip("/").endswith("/focal"):
            raise ValueError("Unexpected distribution series")
        report["publication"] = {
            k: publication.get(k) for k in (
                "source_package_name", "source_package_version", "status",
                "date_published", "date_created", "date_superseded",
                "distro_series_link", "self_link", "source_package_release_link",
            )
        }

        for name, target, kwargs in (
            ("sourceFileUrls", "source_file_urls", {}),
            ("sourceFileUrls", "source_file_urls_with_meta", {"include_meta": "true"}),
            ("changesFileUrl", "changes_file_url", {}),
        ):
            try:
                payload = operation(name, **kwargs)
                urls = urls_from_payload(payload)[:MAX_URLS]
                report[target] = urls[0] if target == "changes_file_url" and urls else (
                    None if target == "changes_file_url" else urls
                )
            except Exception as exc:
                report["lookup_errors"].append(name + ": " + str(exc)[:240])

        try:
            payload = operation("getBuilds")
            for item in payload.get("entries", [])[:32]:
                if item.get("source_package_name", SOURCE) != SOURCE:
                    continue
                if item.get("source_package_version", VERSION) != VERSION:
                    continue
                report["builds"].append({
                    k: (safe_url(item.get(k)) if k.endswith("_url") or k == "self_link"
                        else item.get(k))
                    for k in (
                        "arch_tag", "buildstate", "datebuilt", "date_started",
                        "self_link", "build_log_url", "buildinfo_url",
                        "changesfile_url", "distro_arch_series_link",
                    )
                })
        except Exception as exc:
            report["lookup_errors"].append("getBuilds: " + str(exc)[:240])

        report["result"] = (
            "HISTORIC_PUBLISHING_DATA_COLLECTED"
            if report["publication"] else "INCOMPLETE"
        )
    except Exception as exc:
        report["lookup_errors"].append("fatal: " + str(exc)[:240])
    finally:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
        print("LAUNCHPAD_FORENSICS=" + report["result"])
        print("HISTORIC_BUILDS=" + str(len(report["builds"])))
        print("SOURCE_FILE_URLS=" + str(len(report["source_file_urls"])))
        print("EXACT_SOURCE_FILES_VERIFIED=False")
        for error in report["lookup_errors"]:
            print("LOOKUP_NOTE: " + error, file=sys.stderr)
    return 0 if report["result"] == "HISTORIC_PUBLISHING_DATA_COLLECTED" else 1


if __name__ == "__main__":
    sys.exit(main())
