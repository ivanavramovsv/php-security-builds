#!/usr/bin/env bash
# Read-only, intentionally low-disclosure Oracle VPS PHP compatibility inventory.
# Does not print pool files, phpinfo(), environment, secrets, site names, IPs or ini contents.
# No sudo needed. Does not create files, install packages, or restart processes.
set -u
export LC_ALL=C
export LANG=C

printf 'REPORT=PHP_ARM64_COMPATIBILITY_INVENTORY_V1\n'
printf 'MODE=READ_ONLY\n'
printf 'PRODUCTION_WRITE_OPERATIONS=0\n'
printf 'ARCH=%s\n' "$(uname -m 2>/dev/null || printf unknown)"
if [ -r /etc/os-release ]; then
  . /etc/os-release
  printf 'OS_ID=%s\n' "${ID:-unknown}"
  printf 'OS_VERSION=%s\n' "${VERSION_ID:-unknown}"
fi

for version in 7.4 8.0 8.2; do
  printf '===== PHP_%s =====\n' "$version"
  php_cmd="php$version"
  fpm_cmd="php-fpm$version"
  phpize_cmd="phpize$version"
  printf 'PHP_VERSION_FAMILY=%s\n' "$version"

  if ! command -v "$php_cmd" >/dev/null 2>&1; then
    printf 'CLI_STATUS=NOT_FOUND\n'
  else
    printf 'CLI_STATUS=PRESENT\n'
    "$php_cmd" -r '
      printf("CLI_VERSION=%s\n", PHP_VERSION);
      printf("CLI_PHP_ZTS=%d\n", PHP_ZTS);
      printf("CLI_PHP_DEBUG=%d\n", PHP_DEBUG);
      printf("CLI_PHP_INT_SIZE=%d\n", PHP_INT_SIZE);
      foreach (array("imagick","redis","igbinary","apcu","apc","PDO","pdo_mysql",
          "mysqli","mbstring","intl","curl","zip","gd","dom","SimpleXML",
          "Zend OPcache","sodium","openssl","xml") as $ext) {
        if (extension_loaded($ext)) {
          $v = phpversion($ext);
          printf("CLI_EXTENSION=%s|VERSION=%s\n", $ext, $v === false ? "unreported" : $v);
        }
      }
    ' 2>/dev/null || printf 'CLI_QUERY=ERROR\n'
  fi

  if command -v "$phpize_cmd" >/dev/null 2>&1; then
    printf 'PHPIZE_API='
    "$phpize_cmd" -v 2>/dev/null |
      sed -n 's/^PHP Api Version:[[:space:]]*//p' | head -1
  else
    printf 'PHPIZE_API=NOT_INSTALLED\n'
  fi

  if command -v "$fpm_cmd" >/dev/null 2>&1; then
    printf 'FPM_BINARY=PRESENT\n'
    # Only print FPM-reported module NAMES; never ask php-fpm for phpinfo().
    modules=$("$fpm_cmd" -m 2>/dev/null |
      awk '/^\[PHP Modules\]/{active=1;next}
           /^\[Zend Modules\]/{active=0}
           active && NF { if (n++>0) printf ","; printf "%s", $0 }')
    printf 'FPM_MODULE_NAMES=%s\n' "$modules"
  else
    printf 'FPM_BINARY=NOT_FOUND\n'
  fi

  if command -v systemctl >/dev/null 2>&1; then
    state=$(systemctl is-active "php$version-fpm.service" 2>/dev/null || :)
    printf 'FPM_SERVICE_STATE=%s\n' "${state:-unknown}"
  fi

  # Only inventory dpkg package names and versions for this exact PHP family.
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n' "php$version-*" 2>/dev/null |
      awk '$1=="ii" {printf "INSTALLED_PACKAGE=%s|VERSION=%s\n",$2,$3}' || :
  fi

  if command -v "$php_cmd" >/dev/null 2>&1; then
    # Prevent arbitrary paths being followed from configuration data.
    extdir=$("$php_cmd" -r 'echo ini_get("extension_dir");' 2>/dev/null || :)
    printf 'EXTENSION_DIR_API_SUFFIX=%s\n' "$(basename -- "$extdir" 2>/dev/null || printf unknown)"
    case "$extdir" in
      /usr/lib/php/*|/usr/local/lib/php/*)
        imagick="$extdir/imagick.so"
        if [ -f "$imagick" ] && [ ! -L "$imagick" ]; then
          printf 'IMAGICK_SO_SIZE='
          stat -c %s -- "$imagick" 2>/dev/null || printf 'unknown\n'
          if command -v sha256sum >/dev/null 2>&1; then
            printf 'IMAGICK_SO_SHA256='
            sha256sum -- "$imagick" 2>/dev/null | awk '{print $1}' || :
          fi
          if command -v dpkg-query >/dev/null 2>&1; then
            owner=$(dpkg-query -S "$imagick" 2>/dev/null | head -1 | cut -d: -f1 || :)
            printf 'IMAGICK_SO_PACKAGE=%s\n' "${owner:-NOT_OWNED_BY_DPKG}"
          fi
          if command -v readelf >/dev/null 2>&1; then
            needed=$(readelf -d -- "$imagick" 2>/dev/null |
              sed -n 's/.*(NEEDED).*Shared library: \[\([^]]*\)\].*/\1/p' |
              paste -sd, -)
            printf 'IMAGICK_SO_NEEDED_LIBRARIES=%s\n' "$needed"
          fi
        else
          printf 'IMAGICK_SO_FILE=NOT_FOUND_OR_SYMLINK\n'
        fi ;;
      *) printf 'IMAGICK_SO_FILE=UNUSUAL_EXTENSION_DIR_NOT_INSPECTED\n' ;;
    esac
  fi

  ini_file="/etc/php/$version/fpm/conf.d/99-php2shell-mitigation.ini"
  if [ -r "$ini_file" ] && [ ! -L "$ini_file" ]; then
    mode=$(sed -nE 's/^[[:space:]]*session[.]upload_progress[.]enabled[[:space:]]*=[[:space:]]*([^; #]+).*/\1/p' "$ini_file" |
      tail -1)
    printf 'FPM_UPLOAD_PROGRESS_MITIGATION_FILE=%s\n' "${mode:-UNREADABLE_OR_UNSET}"
  else
    printf 'FPM_UPLOAD_PROGRESS_MITIGATION_FILE=NOT_READABLE\n'
  fi
done

if command -v dpkg >/dev/null 2>&1; then
  if [ -z "$(dpkg --audit 2>/dev/null)" ]; then
    printf 'DPKG_AUDIT=CLEAN\n'
  else
    printf 'DPKG_AUDIT=ATTENTION_NEEDED\n'
  fi
fi
printf 'REPORT_END=YES\n'