# PHP security builds — Ubuntu 20.04 / ARM64

Хранилището съдържа само **GitHub Actions процеси за изолирано компилиране и тестове**, документация и ограниченията за безопасност. **Диагностични скриптове за продукционния сървър не се съхраняват тук.** Те се предоставят отделно в ChatGPT за директно изтегляне.

## Цел

Изследване на безопасен път за PHP 7.4, 8.0 и 8.2 поправки върху Oracle ARM64 Ubuntu 20.04 / HestiaCP, без автоматична промяна на продукционния сървър.

## Оставени GitHub Actions проверки

| Workflow | Предназначение | Проверен резултат |
|---|---|---|
| .github/workflows/upstream-smoke.yml | Минимално компилиране на официален PHP 8.2.35 CLI/FPM | PASS |
| .github/workflows/expanded-php82-smoke.yml | PHP 8.2.35 CLI/FPM с 11 вградени разширения | PASS |
| .github/workflows/imagick-source-provenance.yml | Проверка на официалните PECL Imagick 3.7.0 и 3.8.1 source архиви | PASS |
| .github/workflows/imagick-php82-smoke.yml | Компилиране и PNG roundtrip с Imagick 3.8.1 срещу PHP 8.2.35 | PASS |
| .github/workflows/imagick-370-php82-smoke.yml | Компилиране и PNG roundtrip с продукционната версия Imagick 3.7.0 срещу PHP 8.2.35 | PASS |
| .github/workflows/php82-sidecar-deb-lab.yml | Отделен PHP 8.2.35 + Imagick 3.7.0 Debian пакет, структурен анализ и проверка чрез разархивиране; без инсталиране | PASS |

Успешни изпълнения: [минимален build](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40083395805), [разширен build](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40084823661), [Imagick проверка на източник](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40086739891), [Imagick build и тест](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40087383864).

Това са тестове **в временен GitHub Actions контейнер Ubuntu 20.04 ARM64**. Няма `.deb` пакети за продукционна инсталация; не са компилирани и тествани всички съществуващи на сървъра външни разширения.

## Исторически доказателства и блокери

- Точно идентифициран оригинален PHP 8.2.24 PPA build за Ubuntu 20.04 ARM64: Launchpad 29118485.
- Оригиналният PHP 8.2.24 upstream архив е проверен по SHA-256 от Launchpad source changes.
- Историческата Debian пакетна конфигурация в Salsa е проверен кандидат за сравнение, **не** доказателство за идентичност с оригиналния Ubuntu PPA пакет.
- Оригиналните Ubuntu Focal PPA `.dsc` и `.debian.tar.xz` не са достъпни от проверените официални архиви.
- Проверен комплект от оригинални `.deb` пакети за rollback **липсва** (0/7 проверени файла са налични).
- Реалните HestiaCP/PHP-FPM конфигурации и продукционните разширения не са тествани с новите бинарни файлове.

**DEPLOYMENT_READY = NO**. Успешен upstream тест не е разрешение за инсталация.

## Правила

- Никакви диагностични shell/Python скриптове, тестови отчети или данни от Oracle VPS в това хранилище.
- Само build/test workflows за GitHub Actions; без SSH, Oracle ключове, пароли или автоматичен deployment.
- Без общи `apt upgrade`, `autoremove`, OS upgrade и production промени.
- Изрично одобрение след пълен тест, пакетно сравнение и доказан възстановителен сценарий.
- Промените са в отделен Draft PR. Няма автоматично сливане.

Условия за бъдещо внедряване: [docs/deployment-acceptance-gates.md](docs/deployment-acceptance-gates.md).


## Етап 1J — сравнение с реалната PHP конфигурация на Oracle VPS (24 октомври 2026)

Получен е read-only отчет от оператора за Ubuntu 20.04 ARM64 и PHP-FPM 7.4.33, 8.0.30, 8.2.24. Всички са активни; CLI NTS=0, DEBUG=0, dpkg audit CLEAN; трите PHP версии зареждат Imagick 3.7.0. Версиите, CLI/FPM модули и контролните суми от отчета **не се добавят в това публично хранилище**.

Ключови изводи: PHP 8.2 extension API суфикс 20220829, еднакъв с изолирания PHP 8.2.35; FPM има Imagick 3.7.0; Redis/igbinary/APCu се използват в PHP 7.4/8.0, но не са регистрирани в PHP 8.2. Всички три версии имат mitigation-file стойност 0, което не замества PHP security upgrade.

За да запазим версията на продукционния Imagick, разширихме source provenance workflow да проверява и официалния PECL imagick-3.7.0.tgz:

- PECL Imagick 3.7.0 archive: 360138 байта, SHA-256 `5a364354109029d224bcbb2e82e15b248be9b641227f45e63425c06531792d3e`.
- [Source verification PASS](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40097241137).
- [Изолиран PHP 8.2.35 + Imagick 3.7.0 на Ubuntu 20.04 ARM64: PASS](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40097314536).
- Новият Imagick 3.7.0 се компилира със собствен PHP 8.2.35 `phpize`/`php-config`, зарежда се успешно в CLI и FPM; API `20220829`, NTS, и PNG 2×2 roundtrip PASS.
- `readelf` потвърждава NEEDED имена `libMagickWand-6.Q16.so.6` и `libMagickCore-6.Q16.so.6`, идентични с двете ImageMagick зависимости на реалния сървър.

**Ограничение:** тестът използва ново компилиран Imagick 3.7.0; той **не** доказва, че старият продукционен `imagick.so` ще се зареди в новия PHP, нито че пълното Debian пакетиране е еквивалентно. Изградените файлове са останали само във временния CI контейнер.

**DEPLOYMENT_READY=NO:** историческите PPA Debian sources, пакетните ABI проверки, HestiaCP интеграционните тестове и надежден rollback все още са блокери. На Oracle VPS няма извършени промени.


## Етап 1K — първо успешно лабораторно Debian пакетиране (24 октомври 2026)

[GitHub Actions #40108957712](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40108957712): **PASS**.

- Проверени по SHA-256 официален PHP 8.2.35 и PECL Imagick 3.7.0; Ubuntu 20.04 ARM64.
- Компилирани PHP CLI, PHP-FPM, 11 вградени разширения и външно Imagick 3.7.0 с PHP API 20220829.
- PHP и Imagick са разположени само в отделния CI път `/opt/php82-arm64-sidecar-lab/8.2.35/`.
- Създаден пакет `php82-arm64-sidecar-lab`, версия `8.2.35-0lab1`, ARM64, **25 979 976 байта**.
- SHA-256 на конкретния CI `.deb` артефакт: `24f81aea72d248ec548bcc49d2da8b92855e9be30dc4fe9e0a5c48a0f82f5af8`; това **не е доказателство за възпроизводим байт-по-байт build**.
- `dpkg-shlibdeps` извлече динамичните зависимости, включително `libc6`, `libicu66`, `libssl1.1`, `libmagickwand-6.q16-6` и `libmagickcore-6.q16-6` от Ubuntu 20.04.
- `dpkg-deb --build`, информация за package/version/arch, всички вътрешни пътища, липса на maintainer scripts, извличане с `dpkg-deb -x` и двоично сравнение на `php`/`imagick.so` — **PASS**.

**Не е публикуван или инсталиран `.deb`.** Изтрит е с временната CI среда. Не е предназначен за продукционна инсталация; не замества оригиналните Sury пакети и няма FPM service/pool интеграция. Независима проверка на действителните динамични библиотеки на Oracle VPS и наличието на оригиналните rollback `.deb` все още е нужна.

Детайлно описание: [docs/php82-sidecar-package-lab.md](docs/php82-sidecar-package-lab.md).

**DEPLOYMENT_READY=NO.**


## Етап 1L — лабораторен install/remove и проверка на обратимостта

[GitHub Actions run #40110666079](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40110666079) — PASS за инсталиране, dpkg проверка, зареждане на PHP 8.2.35 и Imagick 3.7.0, PNG roundtrip, премахване и идентичен пакетен инвентар преди и след теста. Всичко се изпълнява само във временния Ubuntu 20.04 ARM64 GitHub контейнер.

**Тестът е на отделния лабораторен sidecar пакет, а не на истинско обновяване на Sury PHP пакети.** Няма инсталация, рестарт или други промени върху Oracle VPS.

Двата успешни .deb build-а имат различни SHA-256 хешове и размери. Независима byte-for-byte възпроизводимост не е доказана и става отделен release gate. Историческият оригинален пакетен rollback остава недостъпен.

Подробности: [docs/php82-sidecar-package-lab.md](docs/php82-sidecar-package-lab.md).

**DEPLOYMENT_READY=NO.**


## Етап 1M — фиксирани метаданни и повторно сглобяване на Debian архива

[GitHub Actions #40113898802, attempt 1](https://github.com/ivanavramovsv/php-security-builds/actions/runs/40113898802) — PASS за две byte-for-byte идентични сглобявания на един и същ staged payload: `SAME_STAGE_DEB_REASSEMBLY=PASS`.

Пакетиращият CI използва фиксирана UTC среда и `SOURCE_DATE_EPOCH=1790000000` (само лабораторен timestamp), нормализира времената на файловете в staging директорията и записва SHA-256 на пакет, payload, PHP CLI, Imagick и control файл.

**Граница:** този PASS доказва само, че архивната операция е детерминистична за един набор от идентични входове. Двата предишни независими `.deb` build-а се различаваха. Затова е нужен повторен CI build при **същия Git SHA** и сравнение на получените binary/payload/deb хешове, преди да говорим за независима възпроизводимост.

Реалният Oracle VPS не е достъпван, няма публикувани `.deb`, няма диагностични скриптове в репото и няма разрешение за продукционен deployment.

**Резултат от независимо повторение на същия Git SHA:** и двете GitHub Actions attempts са PASS за функционалност и идентично двойно пакетиране на един и същ staging tree, но **PHP CLI SHA-256 се различава** между самостоятелните компилации. Imagick 3.7.0 и `DEBIAN/control` са с еднакъв SHA-256. Различават се също payload fingerprint и крайният `.deb`. Следователно независимата build възпроизводимост остава **FAIL / NOT PROVEN**.

[Пълна таблица на двата независими опита](docs/php82-sidecar-package-lab.md#етап-1m--независимо-повторно-компилиране-от-същия-git-sha).

