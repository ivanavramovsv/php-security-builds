#!/usr/bin/env python3
"""Read-only provenance audit. Never builds or deploys .deb files."""
import argparse
import json
import platform
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ARCHIVE = "https://api.launchpad.net/devel/~ondrej/+archive/ubuntu/php"
PACKAGE = "php8.2"
VERSION = "8.2.24-1+ubuntu20.04.1+deb.sury.org+1"
STATUSES = ("Published", "Superseded", "Deleted", "Obsolete")
USER_AGENT = "php-security-builds-provenance-audit/1.0"


def fetch_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=25) as response:
        return json.load(response)


def check_file_url(url):
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            return response.status in (200, 206)
    except Exception:
        # Some archives reject HEAD; try a one-byte ranged request instead.
        request = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Range": "bytes=0-0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                response.read(1)
                return response.status in (200, 206)
        except Exception:
            return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    osinfo = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            osinfo[key] = value.strip('"')

    result = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "architecture": platform.machine(),
        "os": {"ID": osinfo.get("ID"), "VERSION_ID": osinfo.get("VERSION_ID")},
        "target_source": PACKAGE,
        "target_source_version": VERSION,
        "publication": None,
        "source_files": [],
        "errors": [],
        "build_performed": False,
        "production_modified": False,
        "gate": "BLOCKED",
    }

    try:
        if (result["architecture"] != "aarch64"
                or osinfo.get("ID") != "ubuntu"
                or osinfo.get("VERSION_ID") != "20.04"):
            raise RuntimeError("Expected ARM64 runner and Ubuntu 20.04 container")

        matches = []
        for status in STATUSES:
            query = urllib.parse.urlencode({
                "ws.op": "getPublishedSources",
                "source_name": PACKAGE,
                "exact_match": "true",
                "version": VERSION,
                "status": status,
                "ws.size": "100",
            })
            payload = fetch_json(ARCHIVE + "?" + query)
            for entry in payload.get("entries", []):
                if (entry.get("source_package_name") != PACKAGE
                        or entry.get("source_package_version") != VERSION):
                    continue
                if not entry.get("distro_series_link", "").rstrip("/").endswith("/focal"):
                    continue
                matches.append(entry)

        if not matches:
            raise RuntimeError("Exact Focal source publication absent; no substitution allowed")

        rank = {"Published": 0, "Superseded": 1, "Obsolete": 2, "Deleted": 3}
        publication = sorted(matches, key=lambda e: rank.get(e.get("status"), 99))[0]
        result["publication"] = {
            "status": publication.get("status"),
            "self_link": publication.get("self_link"),
            "distro_series_link": publication.get("distro_series_link"),
            "version": publication.get("source_package_version"),
        }

        link = publication.get("self_link")
        if not link or not link.startswith("https://api.launchpad.net/"):
            raise RuntimeError("Missing trusted Launchpad publication link")
        response = fetch_json(link + "?ws.op=sourceFileUrls")
        urls = response if isinstance(response, list) else response.get("entries", [])
        urls = [url for url in urls if isinstance(url, str) and url.startswith("https://")]
        if not urls:
            raise RuntimeError("No original source files downloadable")

        for url in urls:
            name = urllib.parse.unquote(urllib.parse.urlparse(url).path.rsplit("/", 1)[-1])
            result["source_files"].append({
                "name": name, "url": url, "reachable": check_file_url(url)
            })

        if not any(f["name"].endswith(".dsc") and f["reachable"] for f in result["source_files"]):
            raise RuntimeError("Exact .dsc is unavailable")
        if not all(f["reachable"] for f in result["source_files"]):
            raise RuntimeError("One or more original source files are unavailable")

        result["gate"] = "SOURCES_AVAILABLE_FOR_FURTHER_VERIFICATION"
    except Exception as exc:
        result["errors"].append(str(exc))
    finally:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        print("SOURCE_GATE=" + result["gate"])
        for error in result["errors"]:
            print("BLOCKER: " + error, file=sys.stderr)

    return 0 if result["gate"] == "SOURCES_AVAILABLE_FOR_FURTHER_VERIFICATION" else 1


if __name__ == "__main__":
    sys.exit(main())
