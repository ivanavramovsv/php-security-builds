# PHP 7.4 / 8.0 / 8.2 — read-only production compatibility inventory

**Purpose:** establish the real Oracle VPS PHP versions, module versions, API/ABI suffixes, and loaded FPM modules so that a future isolated build can be compared against them.

**Nothing runs on the Oracle VPS without an operator deliberately executing these commands.** GitHub Actions only checks syntax and synthetic fixtures; it cannot reach the VPS.

## Preflight

- Do not run as root or with sudo. A normal SSH shell user is sufficient.
- Review [the exact shell source at the pinned commit](https://github.com/ivanavramovsv/php-security-builds/blob/a303c1e8d17ca93b719b6945d38eb14838e973a0/diagnostics/oracle-php-compatibility-inventory.sh) before executing it.
- The script does not print phpinfo(), FPM pool contents, passwords, environment variables, site names, IP addresses or full PHP INI files.
- A download writes **one temporary script file under /tmp**, but neither the script nor the analyzer changes system configuration, services, databases or installed packages.
- **Do not add the output to the public GitHub repository, issues, CI logs or commits.** The report contains software versions, module names and a binary SHA-256. Review it before sending privately for analysis.

## One-time pinned command on the Oracle VPS

Copy and run these lines in the server's SSH terminal. All source verification must succeed **before** execution:

```bash
OUT=/tmp/oracle-php-compatibility-inventory.sh
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  'https://raw.githubusercontent.com/ivanavramovsv/php-security-builds/a303c1e8d17ca93b719b6945d38eb14838e973a0/diagnostics/oracle-php-compatibility-inventory.sh' \
  --output "$OUT" &&
printf '%s  %s\n' \
  '37bc5e46df447752244542029ab6112799c2d805960430f4240191bb464222d4' \
  "$OUT" | sha256sum --check &&
bash -n "$OUT" &&
bash "$OUT"
```

Expected: `sha256sum: OK` (or filename followed by `OK`), then `MODE=READ_ONLY`, PHP family blocks, and `REPORT_END=YES`. A mismatch **must stop the procedure**. Do not execute an unverified download.

The SHA-256 above was computed from the GitHub source at immutable commit `a303c1e8d17ca93b719b6945d38eb14838e973a0` and cross-checked against a SHA-256 implementation self-test.

Optional cleanup after reviewing the output:

```bash
rm -f /tmp/oracle-php-compatibility-inventory.sh
```

## Fields and limitations

- PHP CLI versions, NTS/debug flags, reported third-party module versions are taken from the CLI runtime only.
- PHP-FPM module names come from `php-fpmX.Y -m`; this is **not an FPM socket request** and does not contact sites or execute user PHP.
- PHP extension API comes from `phpizeX.Y -v` when available, or the extension directory naming convention. Matching API numbers alone do not prove ABI compatibility.
- The script reads the known mitigation file and reports only the value, not its contents. A matching file does not independently prove the effective setting in every FPM pool.
- Imagick `.so` size, SHA-256, package ownership and dynamic library NEEDED names are reported only when its path is under standard PHP extension directories.
- Service activity is queried with `systemctl is-active` only, and package integrity with `dpkg --audit`; no restarts or writes.
- The comparator `diagnostics/compare-inventory.py` can highlight mismatches offline but explicitly always states `PRODUCTION_DEPLOYMENT_READY=NO`.

## Verified tests

- [Focal ARM64 no-PHP smoke + parser tests](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40090247991): PASS.
- [Full mocked PHP 8.2 end-to-end inventory](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40090394591): PASS.

## Remaining release gates

- Exact old Ubuntu Focal source Debian packaging unresolved.
- Verified production-compatible PHP FPM/CLI packages and all needed external modules not built.
- Original exact `.deb` rollback archives not recovered (0 of 7 checked).
- Oracle VPS comparison not yet collected; no claim of actual production compatibility.
- No deployment approval or automation. HestiaCP and websites must remain untouched until a separate explicitly approved controlled rollout.
