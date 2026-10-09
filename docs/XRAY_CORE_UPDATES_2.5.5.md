# Xray Core в Node_Install 2.5.5 — проверка релизов и безопасная политика обновления

Актуальность обзора: **9 октября 2026 года**. Этот документ описывает **официальную реализацию RemnaNode**, а не гарантию совместимости будущих выпусков. Изменения Xray должны проходить отдельное тестирование с конкретным RemnaNode image и Panel.

## 1. Что уже поставляется с RemnaNode

- Проект `remnawave/node` включает Xray Core непосредственно в Docker image, устанавливает исполняемый `/usr/local/bin/xray` и создаёт ссылку `/usr/local/bin/rw-core` на него.
- В просмотренном upstream `docker/Dockerfile` указан `ARG XRAY_CORE_VERSION=v26.7.28`. Это **исходник ветки**, не подтверждение версии уже запущенного digest. Узнайте истинную версию через `docker exec remnanode rw-core version`.
- RemnaNode умеет загружать **управляемый custom Core** через `geodata.core` в Xray-профиле: поля `url` и `sha256`. `CoreLoaderService` загружает бинарник в `.staged`, проверяет digest, устанавливает mode 0755, читает версию, меняет ссылку `rw-core` и создаёт метку источника.
- Если в живой конфигурации `core` отсутствует, менеджер возвращает ссылку `rw-core` к **встроенному** бинарнику.
- Ручная запись внутрь `/usr/local/bin/rw-core` бессмысленна как способ долговременного обновления (это ссылка, контейнер может быть пересоздан). Она также обходит контроль совместимости и rollback.

## 2. Наблюдаемая ситуация в GitHub на 09.10.2026

- В GitHub API `XTLS/Xray-core/releases/latest` стабильным выпуском обозначен `v26.3.27` (опубликован 27.03.2026).
- Более новый `v26.9.30` от 30.09.2026 помечен **pre-release**, а не стабильным выпуском.
- Последний опубликованный `remnawave/node` в GitHub Releases на момент проверки: `3.4.2` (6 октября 2026 года).
- Если в конкретном image установлен Core `v26.7.28`, то сравнение только с `/releases/latest` выдаст *старую stable-версию* и не означает, что нужно делать downgrade. Используйте оба канала вместе с changelog и compatibility matrix.

## 3. Только проверка версий — новая команда

```bash
sudo bash install.sh --xray-versions
sudo bash install.sh --xray-versions --offline
```

Сетевая команда использует HTTPS GitHub API (`/releases?per_page=5` и `/releases/latest`) только для чтения **метаданных**. У неё ограничение по времени и объёму ответа; при ошибке сети — `NOT_VERIFIED`. Она **не скачивает исполняемые бинарники, не правит live Node, панель, Compose, конфиги, не рестартует Xray и не публикует секреты**. Локальная версия берётся от `docker exec remnanode rw-core version`.

Интерпретация вывода:

```text
XRAY_INSTALLED=26.7.28
XRAY_UPSTREAM_NEWEST=26.9.30
XRAY_UPSTREAM_NEWEST_CHANNEL=PRERELEASE
XRAY_UPSTREAM_STABLE=26.3.27
XRAY_UPSTREAM_NEWER=YES
XRAY_UPDATE_ACTION=NONE
XRAY_UPDATE_POLICY=PIN_IMAGE_OR_REVIEW_PANEL_GEODATA_CORE_SHA256
XRAY_NODE_AND_PANEL=UNCHANGED
```

Это **пример формата, не снимок с вашего живого сервера**.

## 4. Рекомендуемый update path №1 — обновление официального RemnaNode image

Это предпочтительный способ поддерживать Core, Node API, Node Plugins и Core-adjacent runtime в согласованном состоянии.

1. Сделать snapshot VPS у хостера и `sudo bash install.sh --backup`.
2. Зафиксировать `docker image inspect`, `docker exec remnanode rw-core version`, выбранный live Panel Config Profile и клиентский canary.
3. Ознакомиться с changelog конкретного образа RemnaNode (в том числе Xray, geodata, protobuf/interface и Node Plugins) и подтвердить совместимость панели/клиентов.
4. На **staging/canary** вызвать существующий `sudo bash install.sh --refresh-image` в согласованном maintenance window. Эта команда выполняет отдельную транзакцию image/Compose, использует digest и rollback state; она **не меняет** SSH, UFW, Nginx, GRUB.
5. Проверить обе конфигурации `RAW → XHTTP → RAW`, Xray/Proxy Protocol v1, HTTPS/HTTP2, API панели, реальные VPN-клиенты, нагрузку/память, timer RKN и сертификаты.
6. При отказе — `sudo bash install.sh --rollback-image` только если состояние транзакции однозначно. Если apply завершился с `UNKNOWN` — сначала ручная диагностика Docker и transaction markers, **не удалять** их.

Обновление Node image **не означает** «обновление до новейшего доступного Xray»: разработчики Node могут отставать от Xray сознательно для совместимости.

## 5. Альтернативный update path №2 — native `geodata.core` RemnaNode

Этот путь — **явный выбор оператора через Panel Config Profile**, без самовольных действий Node_Install. Поле `core` находится внутри `geodata`, которое `CoreLoaderService` разбирает по схеме:

```json
{
  "geodata": {
    "core": {
      "url": "https://YOUR-REVIEWED-HTTPS-HOST.example/xray-linux-amd64",
      "sha256": "REPLACE_WITH_EXACT_SHA256_OF_RAW_EXECUTABLE"
    }
  }
}
```

Это только фрагмент настроек; `url` должен вести на **непосредственно исполняемый файл**, а не на официальный ZIP релиза Xray. **Нельзя** подставлять случайный бинарник или читать checksum с того же неизвестного URL без проверки доверия к публикации. Источник должен быть контролируемым, а хеш — закреплённым после независимой проверки релиза и бинарника. Для amd64/arm64 требуются разные файлы и SHA256. Нужен TLS-сертификат доверенного CA, ограничения доступа к публикации и размеру, журнал изменений и сохранённый предыдущий файл для rollback.

В исходнике upstream `CoreLoaderService` загрузка custom Core завершается без fatal при некоторых ошибках и просто пишет их в лог; **не считайте успешное применение конфигурации доказательством активного custom Core**. После применения обязательно проверить фактический `rw-core version` и workload. При удалении `geodata.core` CoreLoader должен вернуть bundled Core, но эту операцию также проверяйте на staging.

**Перед включением проверять:**

- `core` способен прочитать именно RemnaNode API/internal config, не только `xray run -test` на простом JSON;
- версии Node Plugin API, nft, geodata, outbound/freedom, XHTTP/REALITY/Vision и релевантные security floors;
- невозможность записи/исполнения untrusted remote code от root без review;
- отсутствие второго прослушиваемого 443, сохранение статуса API 2222 и Selfsteal;
- реальная сессия клиента, перезагрузка, Node management/health, rollback, ограничения ресурсов.

В текущем Node_Install **нет** функции, которая автоматически меняет Panel Config Profile или подставляет custom Core — намеренное ограничение целостности production.

## 6. Что нельзя использовать как update

- `curl | bash`, `wget ... -O /usr/local/bin/rw-core`, копирование поверх бинарника работающего контейнера;
- безусловное «последний релиз» из GitHub pre-release в production;
- отключение проверки SHA256/TLS, случайный `latest` без фиксации digest;
- переход на новый протокол/версию Core без проверки клиентских подписок;
- замена `/usr/local/bin/rw-core` host-volume или дополнительным контейнером;
- попытки восстановить service путём удаления `image-transactions` markers.

## 7. Ссылки upstream

- https://github.com/remnawave/node/blob/main/src/modules/xray-core/core-loader.service.ts
- https://github.com/remnawave/node/blob/main/docker/Dockerfile
- https://github.com/remnawave/node/blob/main/docker/rootfs/etc/s6-overlay/scripts/init-env.sh
- https://github.com/XTLS/Xray-core/releases
- https://github.com/XTLS/Xray-examples/tree/main/VLESS-XHTTP-Reality/minimal-steal_others
- https://docs.rw/install/remnawave-node/

**Следующая ревизия Node_Install:** повторно изучить эти ссылки, новое RemnaNode API/Node Plugins, Xray Security Advisories, XHTTP/Golang issue tracker, точную версию внутри Node image и результат CI. Не вносить изменения по одному номеру релиза.
