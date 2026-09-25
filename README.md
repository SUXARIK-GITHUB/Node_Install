# 🚀 Node Install — Remnawave Node

> **Одна команда → 3 значения → автоматическая установка → reboot.**

Скрипт готовит чистую VPS под **Remnawave Node** и профиль **VLESS + RAW + REALITY** с локальным **Nginx Selfsteal**.

## ⚡ Установка

Запустите на VPS **от root**:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/SUXARIK-GITHUB/Node_Install/main/install.sh)
```

Если вошли обычным пользователем:

```bash
sudo -i
```

Скрипт спросит только:

```text
[1/3] SECRET_KEY ноды
[2/3] Публичный IPv4 основной панели Remnawave
[3/3] Домен ноды
```

`SECRET_KEY` вводится скрыто. **IP самой ноды вводить не нужно** — он выбирается автоматически по A-записи домена из публичных IPv4, назначенных VPS.

## 🌐 Перед запуском

- 🖥️ Чистая VPS/VM: Ubuntu 22.04/24.04 или Debian 12/13, systemd + GRUB.
- 💾 Минимум **900 MiB RAM** и **6 GiB** свободного места.
- 🌍 Одна A-запись домена на нужный IPv4 ноды.
- 🚫 AAAA и CDN/Proxy перед нодой должны быть отключены.
- 🔓 Если у хостера есть внешний Firewall / Security Group, разрешите:
  - SSH;
  - `TCP/80` из интернета;
  - `TCP/443` из интернета;
  - `TCP/2222` **только с IPv4 панели Remnawave**.

> `TCP/2222` — внутренний Node API Remnawave. Скрипт ограничивает его в UFW IP-адресом панели, но не может изменить firewall в кабинете хостера.

## 🥷 RAW + REALITY + Selfsteal

Сгенерированный шаблон использует:

```text
VLESS
└── RAW
    └── REALITY :443
        └── target /dev/shm/nginx.sock
            └── Nginx + TLS + обычная веб-страница
```

Основные параметры:

```text
network = raw
target  = /dev/shm/nginx.sock
xver    = 1
```

Порт `443` принадлежит Xray. Nginx не занимает отдельный публичный TLS-порт: REALITY передаёт невалидный/обычный TLS-трафик во внутренний Unix socket через PROXY protocol v1.

Для каждого сервера создаётся локальная страница без внешних CDN и с уникальными per-install параметрами, чтобы все ноды не отдавали байт-в-байт одинаковый контент.

## ✅ Что устанавливается

| | Компонент |
|---|---|
| 🐳 | Docker CE + RemnaNode |
| 🥷 | Nginx Selfsteal через `/dev/shm/nginx.sock` |
| 📜 | Let's Encrypt + автоматическое продление |
| 🛡️ | UFW + Fail2ban |
| 🔒 | Node Port `2222` только для IPv4 панели и выбранного IPv4 ноды |
| 🌐 | Полное отключение IPv6 |
| ⚡ | BBR + `fq` |
| 🕒 | `Europe/Moscow` |
| ♻️ | Reboot каждый понедельник в `04:00` МСК |
| 🧹 | Плановая очистка |
| 🔎 | Проверки до и после reboot |

## 🧩 Настройка Remnawave Panel

Скрипт **не использует API-токен панели** и не создаёт объекты за администратора.

После установки готовые параметры находятся здесь:

```text
/etc/vkarmani-node/profile.json
/etc/vkarmani-node/PANEL-SETUP.txt
```

В панели нужно назначить Node / Config Profile / Host / Internal Squad. Для Host обычно достаточно выбрать нужный inbound, указать домен ноды и оставить Advanced Options по умолчанию; SNI наследуется из inbound.

## 🔎 Проверка

После reboot:

```bash
vkarmani-node-check
```

Строгая проверка после назначения профиля:

```bash
vkarmani-node-check --require-xray
```

Проверка самого Selfsteal socket:

```bash
vkarmani-selfsteal-check
```

Лог после загрузки:

```bash
tail -n 120 /var/log/vkarmani-node-postboot.log
```

## 🔁 Повторный запуск

Эту же команду можно запустить повторно. Сохранённые параметры не спрашиваются заново:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/SUXARIK-GITHUB/Node_Install/main/install.sh)
```

## 🔐 Безопасность

Не публикуйте `SECRET_KEY`, `remnanode.env`, `profile.json`, `reality.json`, приватные сертификаты и полный `docker inspect`.

Подробнее: **[SECURITY.md](SECURITY.md)**.

> ⚠️ Установщик меняет firewall, сеть и параметры загрузки ядра. Перед первым запуском рекомендуется snapshot VPS и доступ к консоли хостера.
