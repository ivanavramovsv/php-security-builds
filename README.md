# PHP security builds — ARM64 / Ubuntu 20.04

**Състояние: Етап 1 — проверка на произхода на източниците; без компилиране и внедряване.**

Това хранилище подготвя възпроизводимо изграждане на защитени PHP `.deb` пакети за работещ Oracle VPS с HestiaCP. Няма достъп до сървъра, не получава негови ключове и не инсталира нищо.

## Фиксирани версии от продукционния сървър

| Версия | Инсталиран пакет | API |
|---|---|---|
| PHP 7.4 | `1:7.4.33-14+ubuntu20.04.1+deb.sury.org+1` | `20190902` |
| PHP 8.0 | `1:8.0.30-8+ubuntu20.04.1+deb.sury.org+1` | `20200930` |
| PHP 8.2 | `8.2.24-1+ubuntu20.04.1+deb.sury.org+1` | `20220829` |

Всички са ARM64 / NTS и използват PHP-FPM. Първият изследван пакет е PHP 8.2.

## Първи етап

Работният процес `.github/workflows/source-audit.yml` се изпълнява на GitHub ARM64 изпълнител с контейнер Ubuntu 20.04. Той:

1. Потвърждава `aarch64` и Ubuntu 20.04.
2. Търси в официалния Launchpad PPA за Ondřej Surý **точната** историческа изходна версия на PHP 8.2.24 за Focal.
3. Проверява дали оригиналните изходни файлове, включително `.dsc`, са достъпни.
4. Независимо от наличието на историческите PPA файлове изтегля официалния PHP 8.2.35 архив и сверява SHA-256. Отделна проверка сверява и оригиналния PHP 8.2.24 архив.
5. Качва диагностичен отчет `php82-source-audit`. Не създава и не публикува двоични пакети.

**Неуспехът на проверката е полезен резултат:** означава, че източниците не са доказани и изграждането е блокирано. Не използвай неподходящи пакети от друга версия на Ubuntu.

## Условия за следващ етап

- Оригиналният изходен пакет от PPA, проверен с `.dsc`, SHA-256 и автентични подписи.
- Оригиналното `debian/` пакетиране и независима проверка на зависимостите.
- Официалните поправки за PHP2Shell и отделна ревизия на пакетите.
- Изграждане в изолирана Ubuntu 20.04 ARM64 среда и проверка на ABI, API, FPM, CLI и външни разширения.
- Оригинални `.deb` пакети за надеждно връщане към предишното състояние.
- Отделно човешко одобрение преди каквато и да е инсталация върху Oracle VPS.

## Правила

- Без SSH, Oracle токени, пароли или конфигурации от сайтовете в GitHub.
- Без автоматично внедряване, `apt upgrade`, `apt autoremove` или `do-release-upgrade` на продукционната машина.
- По време на първия етап комитите са в отделен клон и се преглеждат чрез PR.
- Междинните комити носят `[skip ci]`; последният не го носи, за да стартира проверката.

Източници: https://www.php.net/archive/2026.php и https://launchpad.net/~ondrej/+archive/ubuntu/php

## Резултат от историческата проверка — 24 октомври 2026

В GitHub Actions потвърдихме точно тези ревизии в оригиналния Salsa проект на Debian PHP Team:

- `upstream/8.2.24` → `5e8566cc17eef336fb7d9662274ed716235ff806`
- `debian/8.2.24-1_deb12u1` → `1c00e932a76764e68397b4026a017f114403ad72`

Git и GitLab API върнаха еднакви SHA. Проверени са историческите `debian/changelog`, `debian/control`, `debian/rules` и `debian/patches/series`. Техните SHA-256 отпечатъци вече са фиксирани в `scripts/salsa_history_audit.py`.

Launchpad потвърждава публикацията на точно инсталираната PPA версия за Ubuntu Focal със статус `Superseded`, но `sourceFileUrls` не предоставя оригинални изходни файлове. **Това блокира създаване на продукционни пакети.**

Провереният Debian източник е **кандидат за възстановяване на пакетната структура**, а не доказателство за идентичност с PPA пакета. Следващият етап изисква сравнение на пакетните промени за Focal и на инсталираните версии на зависимостите преди изолирано компилиране.

Стъпките за проверка не правят write операции към Oracle VPS; GitHub Actions не съдържа SSH или deployment credentials.

## Етап 1C — точният оригинален ARM64 build и изходен архив

На 24 октомври 2026 г. потвърдихме оригиналния [Launchpad build 29118485](https://launchpad.net/~ondrej/+archive/ubuntu/php/+build/29118485) (Ubuntu Focal / ARM64, статус `Successfully built`, 27 септември 2024 г.).

Точната историческа [публикация 16505170](https://launchpad.net/~ondrej/+archive/ubuntu/php/+sourcepub/16505170) предоставя **достъпни** `_source.changes`, `_arm64.changes`, `_arm64.buildinfo` и компресиран build log. Техните контролни суми и метаданни се записват в диагностичните GitHub Actions артефакти.

- Изходен `_source.changes` SHA-256: `0fff290f95f22f20191bc799b2f62157b434fb8aea3ddbea51bacfd863da1213`
- Исторически `php8.2_8.2.24-1+ubuntu20.04.1+deb.sury.org+1.dsc`: 5 772 байта; SHA-256 `310a71132026af4299bd7ef9e85cef19aa421bb2a78103934ba23dc3b636fd9f`
- Исторически `php8.2_8.2.24-1+ubuntu20.04.1+deb.sury.org+1.debian.tar.xz`: 70 788 байта; SHA-256 `e1d4f7d158176d9c4d78a425220caf024902136e1f3a3bc18c5057e12aa2853e`
- Оригинален `php8.2_8.2.24.orig.tar.xz`: 12 110 000 байта; SHA-256 `80a5225746a9eb484475b312d4c626c63a88a037d8e56d214f30205e1ba1411a`

**Успешно възстановен:** официалният `https://www.php.net/distributions/php-8.2.24.tar.xz` е байт по байт идентичен на оригиналния `.orig.tar.xz` според SHA-256 от Launchpad.

**Остават недостъпни:** точното Ubuntu PPA `.dsc` и `.debian.tar.xz` (HTTP 404 както от `launchpad.net`, така и от `ppa.launchpadcontent.net`). Наличието на оригиналния build log и на Debian Salsa таговете **не** доказва идентичност на Debian пакетните настройки с оригиналното Focal пакетиране.

Следващо изискване: възстановяване или независимо доказване на съвместимостта на оригиналното Focal `debian/` пакетиране и на връщането към старите `.deb` пакети. Преди това **не се изграждат пакети за внедряване**.

Диагностични проверки:
- [Публикация и build ID](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40081964660)
- [Проверка на ARM64 build метаданните](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40082228917)
- [Проверка на точното SHA-256 на официалния PHP 8.2.24 архив](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40082469880)

GitHub Actions изтегля само изходни/диагностични файлове в краткотраен контейнер, няма сървърни ключове и не инсталира нищо на продукционния Oracle VPS.

## Етап 1D — изследване на зависимостите (read-only)

Документацията на Launchpad уточнява, че **заменени (superseded) версии в PPA подлежат на премахване**, включително изходните им файлове. Затова историческият build лог и `.changes` доказват идентичността на старата версия, но не доказват наличието на необходимия `.debian.tar.xz`.

Скриптът `scripts/historical_builddeps_audit.py` използва точното `arm64.buildinfo`, проверено по фиксиран SHA-256, и сравнява ABI-чувствителните зависимости към **наличните в момента** пакети в чист Ubuntu 20.04 контейнер. Отчетът е само диагностичен: текущите версии може да са се променили от септември 2024 г., а контейнерът не е идентичен с продукционния VPS. Разликите не доказват несъвместимост, но разкриват риска от невъзпроизводими зависимости.

**Окончателният gate остава BLOCKED**, докато не бъдат доказани подходящите Focal пакетни настройки и планът за връщане към старите PHP пакети. Историческото пакетиране в Debian Salsa е полезен източник за разработка, но не разрешава подмяна на работещи системни пакети.

Източници: https://blog.launchpad.net/general/action-back-up-old-sources-from-ppas и https://ubuntu.com/docs/launchpad/developer/explanation/core-components-and-set-up/publisher/ubuntu-archive-publisher/

## Етап 1D — доказан исторически dependency mismatch

[GitHub Actions dependency inventory](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40083125880) сравни SHA-256-проверения оригинален ARM64 `.buildinfo` на PHP 8.2.24 (27.09.2024) с чист контейнер Ubuntu 20.04, без активиран исторически PPA:

- **397** действителни build зависимости;
- **64** проверени ABI/пакетно-чувствителни зависимости;
- **30** съвпадащи и **34** различни или липсващи версии;
- В build-a от 2024 г. има backport/PPA зависимости, включително `libpcre2`, `libxml2`, `libzip`, `libgd`, `libargon2` и `debhelper`.

Тези разлики означават, че чистият Focal контейнер **не възпроизвежда историческата среда**. Самите различия не доказват двоична несъвместимост, а днешните налични версии не дават информация за тези на продукционния Oracle VPS. Документът `reports/historical-builddeps.json` е GitHub Actions артефакт, не е изходен инсталационен план.

## Етап 1E — успешно изолирано upstream smoke изграждане

[GitHub Actions upstream CLI/FPM smoke](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40083395805) е **PASS**: оригиналният `php-8.2.35.tar.xz` е проверен по SHA-256, `./configure --disable-all --enable-cli --enable-fpm --disable-cgi --without-pear` и `make -j2` приключиха успешно в GitHub ARM64 / Ubuntu 20.04, а `sapi/cli/php -v`, `sapi/fpm/php-fpm -v` и CLI smoke тестът показаха PHP 8.2.35.

Това е **минимално upstream компилиране**, а НЕ пакетиране като `.deb`, НЕ тест на всички разширения и НЕ съвместимост със HestiaCP. Изградените файлове се изхвърлят с изолирания runner; публикува се само кратък диагностичен отчет. Няма инсталирани или променени файлове на Oracle VPS.

### Блокиращи задачи преди продукционно внедряване

1. Възстановяване/доказване на правилното Ubuntu 20.04 `debian/` пакетиране и пълната PHP build конфигурация.
2. Валидирани версии и ABI на необходимите системни библиотеки и външни PHP разширения.
3. Пълни ARM64 `.deb` пакети със собствена версия за сигурност, независими пакетни тестове, проверки на PHP-FPM пулове и миграционни тестове.
4. Пълни оригинални архиви за rollback или друго надеждно, предварително проверено възстановяване.
5. Отделно изрично одобрение преди реален `apt install` върху Oracle VPS.

Нито минималното upstream компилиране, нито успешните изследователски задачи отменят `SOURCE_GATE=BLOCKED` на оригиналните PPA архиви.

С цел пестене на GitHub runner ресурси, build workflow се задейства от промени в собствения workflow (или ръчно), а диагностичният изследователски workflow — само при промяна в неговите скриптове или конфигурация.


## Етап 1F — оригинална PHP-FPM конфигурация и реален rollback

[Read-only GitHub Actions audit](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40084580327) — PASS.

- Оригиналният ARM64 build log от 27.09.2024, както и .changes и .buildinfo, са сверени с предварително фиксирани SHA-256 отпечатъци.
- Автоматично разпознати оригинални build цели: apache2-build, cgi-build, cli-build, embed-build, ext-build, fpm-build и phpdbg-build.
- За fpm-build журналът потвърждава --enable-fpm, /etc/php/8.2/fpm, /etc/php/8.2/fpm/conf.d и стандартна systemd/FPM интеграция.
- Историческият debian/rules от Debian PHP Team е потвърден по SHA-256 и е направено синтактично сравнение с build log. Синтактичните различия НЕ доказват ABI несъвместимост и този код НЕ е оригиналният Ubuntu PPA източник.
- Оригиналният ARM64 .changes манифест съдържа SHA-256 на точното множество .deb пакети. При проверка на седем от най-важните (FPM, CLI, Common, OPcache, MySQL, Mbstring, XML) официалните исторически адреси в Launchpad и PPA връщат HTTP 404: **0 от 7 възстановени оригинални пакета**.
- Без подписан или друг проверен архив за оригиналните .deb и без проверен пълен план за възстановяване не е разрешена продукционна инсталация.

Новите проверяващи скриптове се намират в investigations/, а конфигурацията е .github/workflows/repro-inspection.yml. Изпълняват се само при промени в съответните файлове или ръчно, без връзка към Oracle VPS.

Подробните условия за бъдещо внедряване са в [docs/deployment-acceptance-gates.md](docs/deployment-acceptance-gates.md).


## Етап 1G — разширено изолирано компилиране на PHP 8.2.35

[GitHub Actions expanded ARM64 Focal build](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40084823661) — **PASS**.

PHP 8.2.35 е компилиран със значително повече вградени разширения чрез Ubuntu 20.04 ARM64 контейнер. SHA-256 на официалния изходен архив е проверен. CLI и FPM показват версия 8.2.35.

Функционалната PHP проверка потвърди 11 разширения: PDO, pdo_mysql, mysqli, mbstring, intl, OpenSSL, cURL, ZIP, GD, DOM и SimpleXML. Има отделни провал и поправка на конфигурацията: XML/DOM изисква --with-libxml при --disable-all; новият тест след поправката е успешен.

Граници на успешния тест: не са компилирани оригиналните Debian пакети; не е тествано външното Imagick разширение; не е тествана HestiaCP конфигурация; не е доказана ABI/API съвместимост с продукционните модули. Няма автоматично внедряване. Не е публикуван бинарен файл — само диагностичен текстов артефакт.

Следващите критични задачи остават оригиналните Focal пакетни правила, съвместимост с външните разширения и надежден пакетен rollback.

## Етап 1H — външен Imagick 3.8.1 модул срещу PHP 8.2.35: PASS

На 24.10.2026 г. успешно изградихме официалния PECL Imagick 3.8.1 в изолиран Ubuntu 20.04 ARM64 GitHub Actions контейнер срещу PHP 8.2.35, компилиран във временния prefix /tmp/php82-imagick-isolated.

**Източник на Imagick:** pecl.php.net/get/imagick-3.8.1.tgz, 364 008 байта, SHA-256 3a3587c0a524c17d0dad9673a160b90cd776e836838474e173b549ed864352ee. Официалният package.xml потвърждава версията 3.8.1.

**Успешни проверки:**
- Пълно съвпадение на SHA-256 на оригиналните PHP 8.2.35 и PECL Imagick 3.8.1 архиви.
- Временен собствен PHP 8.2.35 CLI/FPM, phpize и php-config: PASS.
- PHP extension API 20220829, NTS.
- Собствен Imagick 3.8.1, компилиран чрез phpize/php-config от PHP 8.2.35: PASS.
- Imagick модулът е зареден чрез PHP CLI и PHP-FPM: PASS.
- PHP създава PNG 2×2 пиксела, записва изображението в паметта и го декодира обратно: IMAGICK_PNG_ROUNDTRIP=PASS.

**GitHub Actions:**
- [Проверка на официалния PECL източник](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40086739891)
- [Успешно PHP 8.2.35 + Imagick 3.8.1 ARM64 компилиране](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40087383864)

**Ограничения:** няма реален HestiaCP FPM pool, не е проверен съществуващият продукционен imagick.so, не е проверена двоична съвместимост с всички използвани PHP разширения, не са изградени Debian пакети и няма промени върху Oracle VPS. Бинарните файлове остават само във временната GitHub среда; артефактите съдържат единствено текстови отчети.

**Продукционният пакетен/rollback gate остава BLOCKED.**

Допълнителна независима историческа следа: официалният GitHub Imagick таг 3.8.1 сочи към commit 70087bab33eab913e99ac77d64d04d1a2fd0b7b0 (https://github.com/Imagick/imagick/releases/tag/3.8.1). Това не доказва байтова идентичност между Git snapshot и PECL tarball; използваният PECL архив е отделно пиннат по SHA-256.

**Следващи задачи:** сравняване на действително инсталирания на Oracle VPS Imagick и другите PHP 8.2 модули само с read-only инвентаризация; после възпроизводим пакетен build и rollback. Подготовката в GitHub не предполага автоматично внедряване.

## Етап 1I — диагностика на реалния Oracle VPS (предстои изпълнение от оператора)

Добавени са два безопасни локални инструмента: 
- [diagnostics/oracle-php-compatibility-inventory.sh](diagnostics/oracle-php-compatibility-inventory.sh) — извежда само PHP версия, PHP API, заглавията и версиите на инсталирани пакети и модули, FPM module names, статуса на FPM, SHA-256 и динамични зависимости на imagick.so, както и стойността от познатия mitigation файл.
- [diagnostics/compare-inventory.py](diagnostics/compare-inventory.py) — сравнява инвентаризацията с известните версии PHP 7.4.33, 8.0.30, 8.2.24 и очакваните API номера, винаги отказва продукционен deployment.

**Проверки:** Bash и Python синтаксис, четири независими offline regression теста, тест в чист Ubuntu 20.04 ARM64 контейнер и интеграционен тест с подменени PHP 8.2 изпълними файлове — всички PASS.

- [CI syntax and offline tests](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40090247991)
- [CI mocked PHP 8.2 integration](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40090394591)

**Важно:** GitHub Actions няма достъп до Oracle VPS. Истинската инвентаризация още не е изпълнявана върху него. Резултатът ѝ не трябва да се качва в публичното GitHub хранилище. След технически преглед на скрипта, той може да се стартира ръчно от SSH без sudo.

**Точните команди с пиннат Git commit и проверка на SHA-256:** [docs/oracle-runtime-compatibility.md](docs/oracle-runtime-compatibility.md).

Пакетният/rollback gate остава BLOCKED; не са внедрявани промени в продукционната машина.
