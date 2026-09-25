# Three inputs before any APT/network/boot changes. No Python/curl dependency here.
# This file is embedded in install.sh, not downloaded at run time.
vk_input_error() { printf 'ОШИБКА: %s\n' "$*" >&2; return 1; }
vk_trim() {
    local value=$1
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}
vk_validate_ipv4() {
    local value=$1 octet
    local -a parts=()
    [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -r -a parts <<< "$value"
    for octet in "${parts[@]}"; do
        [[ "$octet" == 0 || "$octet" != 0* ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
    # Early reject of local/reserved addresses. Python revalidates is_global after APT.
    ((parts[0] > 0 && parts[0] < 224)) || return 1
    case "$value" in
        10.*|127.*|169.254.*|192.168.*|192.0.0.*|192.0.2.*|198.51.100.*|203.0.113.*) return 1 ;;
    esac
    if ((parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31)); then return 1; fi
    if ((parts[0] == 100 && parts[1] >= 64 && parts[1] <= 127)); then return 1; fi
    if ((parts[0] == 198 && (parts[1] == 18 || parts[1] == 19))); then return 1; fi
}
vk_validate_domain() {
    local value=$1 part
    local -a parts=()
    [[ ${#value} -le 253 && "$value" == *.* && "$value" != .* && "$value" != *. && "$value" != *..* ]] || return 1
    [[ ! "$value" =~ ^[0-9.]+$ ]] || return 1
    IFS=. read -r -a parts <<< "$value"
    for part in "${parts[@]}"; do
        [[ ${#part} -ge 1 && ${#part} -le 63 && "$part" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    done
}
vk_restore_tty() {
    if [[ -n "${VK_TTY_STATE:-}" && -n "${VK_TTY_FD:-}" ]]; then
        stty "$VK_TTY_STATE" <&"$VK_TTY_FD" 2>/dev/null || true
        VK_TTY_STATE=''
    fi
}
vk_collect_inputs() {
    # Never inherit exported attributes or tracing for a credential variable.
    set +x
    set +a
    unset VK_INPUT_SECRET VK_INPUT_PANEL_IPV4 VK_INPUT_DOMAIN
    VK_INPUT_SECRET='' VK_INPUT_PANEL_IPV4='' VK_INPUT_DOMAIN=''
    if [[ -s "$ETC/config.json" ]]; then
        printf 'Повторный запуск: используются сохранённые параметры; вопросов нет.\n'
        return 0
    fi
    command -v stty >/dev/null || { vk_input_error 'Требуется stty (coreutils).'; return 1; }
    exec {VK_TTY_FD}<>/dev/tty || { vk_input_error 'Нужен интерактивный SSH-терминал (при ssh-команде используйте ssh -t).'; return 1; }
    VK_TTY_STATE=$(stty -g <&"$VK_TTY_FD") || return 1
    trap 'vk_restore_tty' EXIT
    trap 'vk_restore_tty; exit 130' INT
    trap 'vk_restore_tty; exit 143' TERM
    trap 'vk_restore_tty; exit 129' HUP
    printf '\nVKarmani: SECRET_KEY → IPv4 основного сервера → домен ноды.\n' >&"$VK_TTY_FD"
    printf 'После трёх значений — автоматическая установка и reboot. Нужны снимок VPS и консоль хостера.\n' >&"$VK_TTY_FD"
    printf 'Будут изменены firewall/загрузка, отключён IPv6; условия Let\047s Encrypt принимаются автоматически.\n' >&"$VK_TTY_FD"
    printf 'IPv4 основного сервера — исходящий адрес backend панели, НЕ Cloudflare и НЕ IP этой ноды.\n\n' >&"$VK_TTY_FD"
    # Noncanonical mode also permits long (>4096 byte) single-line SECRET_KEY bundles.
    # Disable echo BEFORE displaying the prompt, so immediate paste cannot reveal the key.
    stty -echo -icanon min 1 time 0 <&"$VK_TTY_FD"
    printf '[1/3] SECRET_KEY ноды (скрытый ввод): ' >&"$VK_TTY_FD"
    if ! IFS= read -r -u "$VK_TTY_FD" VK_INPUT_SECRET; then
        vk_restore_tty; vk_input_error 'Ввод SECRET_KEY прерван.'; return 1
    fi
    vk_restore_tty
    printf '\n' >&"$VK_TTY_FD"
    VK_INPUT_SECRET=$(vk_trim "$VK_INPUT_SECRET")
    if [[ "$VK_INPUT_SECRET" == SECRET_KEY=* ]]; then VK_INPUT_SECRET=${VK_INPUT_SECRET#SECRET_KEY=}; fi
    if [[ "$VK_INPUT_SECRET" == \"*\" || "$VK_INPUT_SECRET" == \'*\' ]]; then
        VK_INPUT_SECRET=${VK_INPUT_SECRET:1:${#VK_INPUT_SECRET}-2}
    fi
    [[ ${#VK_INPUT_SECRET} -ge 64 && ${#VK_INPUT_SECRET} -le 65536 && "$VK_INPUT_SECRET" =~ ^[A-Za-z0-9_+/=-]+$ ]] || {
        unset VK_INPUT_SECRET; vk_input_error 'Некорректный формат SECRET_KEY. Вставьте значение из панели одной строкой.'; return 1;
    }
    printf '[2/3] Публичный IPv4 основного сервера (панели): ' >&"$VK_TTY_FD"
    IFS= read -r -u "$VK_TTY_FD" VK_INPUT_PANEL_IPV4 || { vk_input_error 'Ввод IPv4 прерван.'; return 1; }
    VK_INPUT_PANEL_IPV4=$(vk_trim "$VK_INPUT_PANEL_IPV4")
    vk_validate_ipv4 "$VK_INPUT_PANEL_IPV4" || { vk_input_error 'Нужен публичный IPv4 панели, без порта, CIDR и https://.'; return 1; }
    printf '[3/3] Домен ноды (например, ee1.example.com): ' >&"$VK_TTY_FD"
    IFS= read -r -u "$VK_TTY_FD" VK_INPUT_DOMAIN || { vk_input_error 'Ввод домена прерван.'; return 1; }
    VK_INPUT_DOMAIN=$(vk_trim "$VK_INPUT_DOMAIN")
    VK_INPUT_DOMAIN=${VK_INPUT_DOMAIN,,}; VK_INPUT_DOMAIN=${VK_INPUT_DOMAIN%.}
    vk_validate_domain "$VK_INPUT_DOMAIN" || { vk_input_error 'Некорректный домен: без https://, порта и пути; IDN в punycode.'; return 1; }
    exec {VK_TTY_FD}>&-
    unset VK_TTY_FD
    trap - EXIT INT TERM HUP
    printf '\nВсе три значения приняты. Далее вопросов нет; SECRET_KEY не выводится.\n'
}
