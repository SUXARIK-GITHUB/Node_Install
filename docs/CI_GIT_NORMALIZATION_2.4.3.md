# CI fix 2.4.3 — Git text normalization vs release SHA256 manifest

## Симптом

После публикации 2.4.2 все обязательные GitHub Actions job остановились в шаге `Verify Git checkout and release files` до запуска `tests/run.sh`.

`sha256sum --check SHA256SUMS` сообщил ровно три mismatch:

- `docs/evidence/241-ci-ubuntu22-failure.txt`
- `docs/evidence/241-ci-ubuntu24-failure.txt`
- `docs/evidence/241-ci-ubuntu26-userspace-failure.txt`

## Причина

В ZIP 2.4.2 эти три пользовательских CI-лога были сохранены с CRLF. Их SHA-256 в `SHA256SUMS` был рассчитан по CRLF-байтам. При этом `.gitattributes` содержит `* text=auto`, поэтому Git считает эти `.txt` текстом и при commit/checkout хранит/выдаёт canonical LF. В результате ZIP-проверка проходила, а clean Git checkout имел другие байты и закономерно не совпадал с manifest.

Это release-packaging/validation defect. Production installer, Docker, RemnaNode, NET_ADMIN, Nginx, Selfsteal, certificate deploy, firewall, SSH и network policy к этому отказу отношения не имеют.

## Исправление 2.4.3

1. Три evidence-файла нормализованы в LF до расчёта manifest.
2. `SHA256SUMS` пересобирается только после окончательной фиксации файлов релиза.
3. В test suite добавлена проверка `test_manifest_text_files_are_git_canonical_lf`: UTF-8 text entries из manifest не должны содержать CR/CRLF.
4. Release-validation включает реальный Git round-trip: временный repository → `git add`/commit → clean clone/checkout → `sha256sum --check SHA256SUMS`.

## Почему не используется `-text`

Evidence-файлы являются обычным текстом. Принудительное отключение Git normalization только ради сохранения случайных CRLF-байтов создало бы исключение в supply-chain без эксплуатационной пользы. Нормализация в LF соответствует существующей политике репозитория и делает ZIP и Git checkout согласованными.

## Граница изменения

2.4.3 не меняет production transport/runtime. Исправление относится к release bytes, manifest, CI regression и version metadata. Работающие ноды не требуют server-side repair только ради 2.4.3.
