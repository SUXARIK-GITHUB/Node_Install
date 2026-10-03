# CI fix 2.4.2 — PROXY v1 boundary vs fragmented TLS ClientHello

Дата: **2026-10-03**.

## Фактический CI-инцидент 2.4.1

После публикации 2.4.1 все три обязательных job дошли до одного и того же единственного тестового отказа:

| Job | Python | Nginx | Результат |
|---|---:|---:|---|
| Ubuntu 22.04 | 3.10.12 | 1.18.0 | 555 PASS, 1 ERROR |
| Ubuntu 24.04 | 3.12.3 | 1.24.0 | 555 PASS, 1 ERROR |
| Ubuntu 26 userspace | 3.14.4 | 1.28.3 | 555 PASS, 1 ERROR |

Во всех трёх случаях ошибка одна: `test_large_fragmented_clienthello_and_proxy_header` получал `BrokenPipeError` при отправке TLS bytes. Полные присланные журналы сохранены без сокращения:

- `evidence/241-ci-ubuntu22-failure.txt`
- `evidence/241-ci-ubuntu24-failure.txt`
- `evidence/241-ci-ubuntu26-userspace-failure.txt`

Важно: исправленные в 2.4.1 тесты certificate reload в этих же прогонах проходят. Следовательно, это отдельный CI-contract defect, а не возврат предыдущей ошибки.

## Настоящая причина

Старый synthetic test сначала делил строку PROXY v1 на записи по 7 байт:

```text
PROXY T
CP4 127
...
```

а уже затем делил большой TLS ClientHello по 37 байт. UNIX `SOCK_STREAM` не сохраняет границы `sendall()`. На быстром локальном запуске несколько коротких writes могли попасть к Nginx одним read и создавали ложное ощущение, что fragmented PROXY v1 поддерживается. На GitHub runner Nginx успевал прочитать первый неполный кусок.

Детерминированное локальное воспроизведение добавило 10 ms между кусками PROXY header. Результат:

```text
CLIENT_RESULT=BrokenPipeError: [Errno 32] Broken pipe
NGINX_RESULT=... broken header: "PROXY T" while reading PROXY protocol ...
```

Evidence: `evidence/242-proxy-fragment-reproduction.txt`.

Это объясняет все три CI job одной причиной и не требует маскировать `BrokenPipeError`.

## Почему production transport не меняется

Generated Nginx по-прежнему принимает PROXY protocol на локальном Selfsteal UNIX socket, а generated REALITY fallback использует `xver=1`.

Upstream Xray VLESS fallback для `xver=1` сначала формирует полную строку PROXY v1 в отдельном buffer и вызывает `serverWriter.WriteMultiBuffer(buf.MultiBuffer{pro})`; только после этого выполняется `buf.Copy(reader, serverWriter, ...)` для fallback payload. Поэтому корректный интеграционный boundary — полный PROXY header, затем TLS payload, а не искусственная fragmentation внутри строки PROXY.

Использованные upstream файлы при разборе:

- `XTLS/Xray-core/proxy/vless/inbound/inbound.go`
- `XTLS/Xray-core/common/buf/io.go`

Это наблюдение относится к проверенному upstream состоянию на дату разбора и не заменяет pin/тест конкретного RemnaNode/Xray image.

## Исправление 2.4.2

Тест переименован в:

```text
test_large_fragmented_clienthello_after_complete_proxy_header
```

Новый порядок:

1. соединиться с private Nginx UNIX socket;
2. отправить полную PROXY v1 строку одним `sendall()`;
3. выдержать 10 ms, чтобы Nginx гарантированно мог обработать header отдельно от TLS;
4. сформировать большой TLS 1.3 ClientHello через `ssl.MemoryBIO`;
5. отправлять TLS bytes чанками по 37 байт с 1 ms между чанками;
6. завершить настоящий TLS handshake;
7. подтвердить ALPN `http/1.1`;
8. выполнить HEAD и получить HTTP 200.

Таким образом, TLS fragmentation не удалена и не заменена mock-ом. Наоборот, теперь она принудительно проявляется и не зависит от случайного coalescing сокета.

## Что НЕ менялось

- Nginx production template;
- `proxy_protocol` на Selfsteal socket;
- REALITY `xver=1`;
- RemnaNode Docker Compose;
- default `NET_ADMIN` из 2.4.0;
- cert-deploy convergence 2.4.1;
- UFW/Fail2ban/SSH/network policy;
- runtime packages/dependencies;
- публичные порты и systemd topology.

На уже работающей 2.4.1 ноде отдельное server-side применение 2.4.2 не требуется только ради этого CI fix.

## Acceptance для релиза

Перед упаковкой 2.4.2 обязательно:

- targeted fragmented-TLS test многократно — PASS;
- полный `tests/run.sh` root — PASS;
- полный `tests/run.sh` UID 1000 — PASS;
- `bash -n`, Python compile/AST, JSON/YAML parse — PASS;
- `SHA256SUMS` — PASS после фиксации дерева;
- fresh-extract ZIP test — PASS;
- затем удалённый GitHub matrix 22.04 / 24.04 / 26 userspace.

Удалённый matrix нельзя считать пройденным до фактического push нового дерева.
