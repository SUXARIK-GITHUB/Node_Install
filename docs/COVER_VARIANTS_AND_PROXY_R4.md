# Шесть статических сайтов и независимый локальный Nginx reverse proxy (r4)

Подробная карта: [R4_8_POINT_ENGINEERING_20261015.md](R4_8_POINT_ENGINEERING_20261015.md).

### Границы

`cover-variants` — шесть дополнительных вариантов HTML/CSS. Они не заменяют текущую страницу под `/var/www/vkarmani-node/site` без отдельного утверждения дизайна и контролируемого test→backup→rollback. Скрипт `scripts/cover_variants.py` выводит preview только в **новую** папку вне живого Nginx. Он не устанавливает ничего на VPS.

`nginx_proxy_plan.py` генерирует валидируемые конфигурации на 127.0.0.1 и не запускает `nginx -s reload`. Стандартный Nginx `stream` должен быть установлен как модуль и быть включён на верхнем уровне. Нельзя помещать блок `stream {}` внутри `/etc/nginx/conf.d` обычного Debian/Ubuntu `http {}`; для применения потребуется отдельный root-owned top-level include, backup `nginx.conf`, `nginx -t`, `systemctl reload nginx` **только на тестовой VPS**. Не направлять upstream на сам listener, не захватывать 80/443/2222, не менять fallback Unix-socket.

### Test-only команды

```bash
python3 scripts/cover_variants.py --list
python3 scripts/cover_variants.py --name 03-observatory --output /tmp/vk-cover-observatory-new
python3 scripts/nginx_proxy_plan.py --kind http --listen 9000 --backend 9100 --output /tmp/vk-http-new.conf
python3 scripts/nginx_proxy_plan.py --kind tcp --listen 9200 --backend 9300 --output /tmp/vk-stream-new.conf
```

**Статус:** статические файлы и генерация — offline PASS после тестов; Nginx binary parsing, реальные загрузка/SSL/HTTP/stream подключения и production deployment — BLOCKED без отдельной staging VM и согласованного сетевого плана.
