#!/usr/bin/env bash
# ONLY run in disposable GitHub CI. Creates fake executables in temporary dir.
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

cat > "$tmp/php8.2" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "-r" ]; then
  case "$2" in
    *'ini_get("extension_dir")'*)
      printf '/usr/lib/php/20220829';;
    *)
      printf 'CLI_VERSION=8.2.24\n'
      printf 'CLI_PHP_ZTS=0\n'
      printf 'CLI_PHP_DEBUG=0\n'
      printf 'CLI_PHP_INT_SIZE=8\n'
      printf 'CLI_EXTENSION=imagick|VERSION=3.7.0\n'
      printf 'CLI_EXTENSION=openssl|VERSION=8.2.24\n'
      ;;
  esac
else
  exit 1
fi
EOF
cat > "$tmp/php-fpm8.2" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "-m" ]; then
  printf '[PHP Modules]\nimagick\nmysqli\nmbstring\n[Zend Modules]\nZend OPcache\n'
else
  exit 1
fi
EOF
cat > "$tmp/phpize8.2" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "-v" ]; then
  printf 'Configuring for:\nPHP Api Version:         20220829\nZend Module Api No:      20220829\n'
else
  exit 1
fi
EOF
chmod 700 "$tmp/php8.2" "$tmp/php-fpm8.2" "$tmp/phpize8.2"
PATH="$tmp:$PATH" bash diagnostics/oracle-php-compatibility-inventory.sh > "$tmp/inventory.txt"
python3 diagnostics/compare-inventory.py "$tmp/inventory.txt" > "$tmp/analysis.txt"

grep -Fx 'CLI_VERSION=8.2.24' "$tmp/inventory.txt"
grep -Fx 'CLI_EXTENSION=imagick|VERSION=3.7.0' "$tmp/inventory.txt"
grep -Fx 'PHPIZE_API=20220829' "$tmp/inventory.txt"
grep -Fx 'FPM_MODULE_NAMES=imagick,mysqli,mbstring' "$tmp/inventory.txt"
grep -Fx 'PHP_8_2_API_EVIDENCE=MATCH' "$tmp/analysis.txt"
grep -Fx 'PHP_8_2_INSTALLED_IMAGICK_VERSION=3.7.0' "$tmp/analysis.txt"
grep -Fx 'PHP_8_2_FPM_IMAGICK=YES' "$tmp/analysis.txt"
grep -Fx 'PRODUCTION_DEPLOYMENT_READY=NO' "$tmp/analysis.txt"
echo 'MOCKED_PHP82_END_TO_END=PASS'
