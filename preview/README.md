# Preview Selfsteal 2.2.0

Это нейтральные демонстрационные страницы `node.example.com`, не данные VPS. Откройте [gallery.html](gallery.html), затем один из вариантов. Каждый index создан тем же встроенным renderer, что и installer; локальные CSS/SVG работают без backend. На сервере вариант выбирается случайно один раз и сохраняется. Здесь фиксированные тестовые seeds позволяют показать все четыре оформления.

- [Orbit](variants/orbit/index.html) — тёмные кольца.
- [Fold](variants/fold/index.html) — светлая геометрия.
- [Grid](variants/grid/index.html) — синяя композиция.
- [Horizon](variants/horizon/index.html) — фиолетовые арки.

Снимки находятся в `screenshots/`. Внешних запросов, JS, cookies и форм нет. Браузерная проверка использует HTML в памяти с точным CSS; TLS/MIME/cache проверены отдельно локальным Nginx. Это не сквозной REALITY-проход. [Отчёт браузера](browser-report.json).

`history-2.1.3` содержит прежний preview побайтово. Старые assets на корневом уровне сохранены ради полноты входного проекта; текущий index ссылается только на актуальные ресурсы. Папка preview не устанавливается на VPS: все рабочие ресурсы встроены в install.sh. Не копируйте preview в действующий webroot вручную.
