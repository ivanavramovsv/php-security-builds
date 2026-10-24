#!/usr/bin/env python3
"""Audit public Debian PHP Team historical tags; NEVER claim PPA equivalence.

No binaries are built, no packages are installed. Only source metadata, selected
packaging file hashes, and provenance evidence are written.
"""
import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPOSITORY = "https://salsa.debian.org/php-team/php.git"
GITLAB_API = "https://salsa.debian.org/api/v4/projects/php-team%2Fphp"
TAGS = {
    "upstream": "upstream/8.2.24",
    "debian": "debian/8.2.24-1_deb12u1",
}
PACKAGING_FILES = ("debian/changelog", "debian/control", "debian/rules", "debian/patches/series")
EXPECTED_DEBIAN_CHANGELOG = re.compile(r"^php8[.]2 [(]8[.]2[.]24-1~deb12u1[)]")
USER_AGENT = "php-security-builds-history-check/1.0"


def read_bytes(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=35) as response:
        return response.read(2_000_001)


def git_remote_tag(tag):
    ref = "refs/tags/" + tag
    proc = subprocess.run(
        ["git", "ls-remote", "--tags", "--exit-code", REPOSITORY, ref, ref + "^{}"],
        text=True, capture_output=True, timeout=45, check=True,
    )
    tags = {refname: sha for sha, refname in (line.split("\t", 1) for line in proc.stdout.splitlines() if "\t" in line)}
    result = tags.get(ref + "^{}") or tags.get(ref)
    if not result or not re.fullmatch("[0-9a-f]{40}", result):
        raise RuntimeError("No valid SHA for remote tag " + tag)
    return result


def gitlab_tag(tag):
    tag_part = urllib.parse.quote(tag, safe="")
    url = GITLAB_API + "/repository/tags/" + tag_part
    data = json.loads(read_bytes(url))
    commit = data.get("commit", {}).get("id")
    if data.get("name") != tag or not isinstance(commit, str) or not re.fullmatch("[0-9a-f]{40}", commit):
        raise RuntimeError("GitLab tag mismatch: " + tag)
    return commit


def gitlab_raw(path, tag):
    encoded_path = urllib.parse.quote(path, safe="")
    ref = urllib.parse.quote(tag, safe="")
    return read_bytes(GITLAB_API + "/repository/files/" + encoded_path + "/raw?ref=" + ref)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    out = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "architecture": platform.machine(),
        "source_repository": REPOSITORY,
        "source_project": "Debian PHP Team / php",
        "target_ppa_version": "8.2.24-1+ubuntu20.04.1+deb.sury.org+1",
        "exact_ubuntu_ppa_packaging_recovered": False,
        "production_modified": False,
        "build_performed": False,
        "tag_evidence": {},
        "debian_packaging_files": [],
        "errors": [],
        "gate": "BLOCKED",
    }
    try:
        if out["architecture"] != "aarch64":
            raise RuntimeError("Require native aarch64 executor")
        for kind, tag in TAGS.items():
            checks = {"tag_name": tag, "git_sha": None, "gitlab_api_sha": None}
            for key, fn in (("git_sha", git_remote_tag), ("gitlab_api_sha", gitlab_tag)):
                try:
                    checks[key] = fn(tag)
                except Exception as exc:
                    checks.setdefault("lookup_errors", []).append(key + ": " + str(exc))
            out["tag_evidence"][kind] = checks
            if not checks["git_sha"] or not checks["gitlab_api_sha"]:
                raise RuntimeError("Unable to independently validate Salsa tag: " + tag)
            if checks["git_sha"] != checks["gitlab_api_sha"]:
                raise RuntimeError("Git / GitLab API tag SHA disagreement: " + tag)

        for path in PACKAGING_FILES:
            try:
                data = gitlab_raw(path, TAGS["debian"])
            except Exception as exc:
                if path == "debian/patches/series":
                    out["debian_packaging_files"].append({"path": path, "available": False, "reason": str(exc)})
                    continue
                raise RuntimeError("Cannot inspect historical packaging file " + path + ": " + str(exc))
            if len(data) > 2_000_000:
                raise RuntimeError("Unexpected packaging file size: " + path)
            meta = {
                "path": path, "available": True, "length": len(data),
                "sha256": hashlib.sha256(data).hexdigest()
            }
            if path == "debian/changelog":
                first = data.decode("utf-8").splitlines()[0]
                meta["first_line"] = first
                if not EXPECTED_DEBIAN_CHANGELOG.match(first):
                    raise RuntimeError("Historical Debian changelog version differs: " + first)
            out["debian_packaging_files"].append(meta)

        out["gate"] = "DEBIAN_TAG_AND_PACKAGING_VERIFIED_PPA_NOT_EQUIVALENT"
    except Exception as exc:
        out["errors"].append(str(exc))
    finally:
        filename = Path(args.output)
        filename.parent.mkdir(parents=True, exist_ok=True)
        filename.write_text(json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        print("HISTORICAL_GATE=" + out["gate"])
        for e in out["errors"]:
            print("BLOCKER: " + e, file=sys.stderr)
        print("EXACT_PPA_PACKAGING_RECOVERED=False")
        print("BUILD_PERFORMED=False")
    return 0 if out["gate"] == "DEBIAN_TAG_AND_PACKAGING_VERIFIED_PPA_NOT_EQUIVALENT" else 1


if __name__ == "__main__":
    sys.exit(main())
