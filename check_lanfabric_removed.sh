#!/usr/bin/env bash
set -u

WG_IF="wg0"
REMOTE_DIR="/opt/vpn-admin"
BACKEND_FILE="/opt/vpn-admin/backend"
WG_DIR="/etc/wireguard"
SUDOERS_FILE="/etc/sudoers.d/vpn-admin"
SYSCTL_FILE="/etc/sysctl.d/99-vpn-forward.conf"

VPN_NET="10.8.0.0/24"
WG_PORT="51820"

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

pkg_installed() {
    dpkg -s "$1" >/dev/null 2>&1
}

any_pkg_installed() {
    local pkg
    for pkg in "$@"; do
        if pkg_installed "$pkg"; then
            return 0
        fi
    done
    return 1
}

path_exists() {
    [ -e "$1" ]
}

dir_has_files() {
    [ -d "$1" ] && find "$1" -mindepth 1 -print -quit 2>/dev/null | grep -q .
}

interface_exists() {
    ip link show "$WG_IF" >/dev/null 2>&1
}

module_loaded() {
    lsmod | awk '{print $1}' | grep -qx "$1"
}

iptables_has_lanfabric_rules() {
    iptables -S FORWARD 2>/dev/null | grep -q "$WG_IF" && return 0
    iptables -t nat -S POSTROUTING 2>/dev/null | grep -q "$VPN_NET" && return 0
    return 1
}

port_listening() {
    ss -ulnH 2>/dev/null | grep -q ":${WG_PORT}\b"
}

systemd_has_wg_quick() {
    systemctl list-unit-files 2>/dev/null | grep -q "wg-quick@"
}

systemd_wg_active() {
    systemctl is-active "wg-quick@${WG_IF}" >/dev/null 2>&1
}

amnezia_repo_exists() {
    ls /etc/apt/sources.list.d/amnezia-ubuntu-ppa*.list >/dev/null 2>&1
}

detect_original_backend() {
    if [ -f "$BACKEND_FILE" ]; then
        cat "$BACKEND_FILE" 2>/dev/null | tr -d '[:space:]'
        return
    fi

    if has_cmd awg || any_pkg_installed amneziawg amneziawg-tools amneziawg-dkms || module_loaded amneziawg || amnezia_repo_exists; then
        echo "awg"
        return
    fi

    if has_cmd wg || any_pkg_installed wireguard wireguard-tools wireguard-dkms || module_loaded wireguard || systemd_wg_active; then
        echo "wg"
        return
    fi

    if grep -Rqs "amnezia" "$WG_DIR" "$REMOTE_DIR" 2>/dev/null; then
        echo "awg"
        return
    fi

    if dir_has_files "$WG_DIR" || path_exists "$REMOTE_DIR" || path_exists "$SUDOERS_FILE" || path_exists "$SYSCTL_FILE"; then
        echo "unknown"
        return
    fi

    echo "none"
}

print_check() {
    local name="$1"
    local result="$2"

    if [ "$result" = "1" ]; then
        printf "  [есть] %s\n" "$name"
    else
        printf "  [нет ] %s\n" "$name"
    fi
}

main() {
    local backend
    backend="$(detect_original_backend)"

    local awg_installed=0
    local wg_installed=0
    local runtime_present=0
    local config_present=0
    local package_present=0

    if has_cmd awg || any_pkg_installed amneziawg amneziawg-tools amneziawg-dkms || module_loaded amneziawg || amnezia_repo_exists; then
        awg_installed=1
    fi

    if has_cmd wg || any_pkg_installed wireguard wireguard-tools wireguard-dkms || module_loaded wireguard; then
        wg_installed=1
    fi

    if interface_exists || iptables_has_lanfabric_rules || port_listening || systemd_wg_active; then
        runtime_present=1
    fi

    if path_exists "$REMOTE_DIR" || path_exists "$WG_DIR" || path_exists "$SUDOERS_FILE" || path_exists "$SYSCTL_FILE"; then
        config_present=1
    fi

    if [ "$awg_installed" = "1" ] || [ "$wg_installed" = "1" ]; then
        package_present=1
    fi

    echo "Проверка удаления LanFabric"
    echo "Backend: ${backend}"
    echo

    echo "Следы AmneziaWG:"
    print_check "команда awg" "$(has_cmd awg && echo 1 || echo 0)"
    print_check "пакеты amneziawg/amneziawg-tools/amneziawg-dkms" "$(any_pkg_installed amneziawg amneziawg-tools amneziawg-dkms && echo 1 || echo 0)"
    print_check "модуль amneziawg загружен" "$(module_loaded amneziawg && echo 1 || echo 0)"
    print_check "PPA AmneziaWG" "$(amnezia_repo_exists && echo 1 || echo 0)"
    echo

    echo "Следы WireGuard:"
    print_check "команда wg" "$(has_cmd wg && echo 1 || echo 0)"
    print_check "пакеты wireguard/wireguard-tools/wireguard-dkms" "$(any_pkg_installed wireguard wireguard-tools wireguard-dkms && echo 1 || echo 0)"
    print_check "модуль wireguard загружен" "$(module_loaded wireguard && echo 1 || echo 0)"
    print_check "systemd wg-quick" "$(systemd_has_wg_quick && echo 1 || echo 0)"
    echo

    echo "Runtime-состояние:"
    print_check "интерфейс ${WG_IF}" "$(interface_exists && echo 1 || echo 0)"
    print_check "UDP-порт ${WG_PORT}" "$(port_listening && echo 1 || echo 0)"
    print_check "iptables-правила LanFabric" "$(iptables_has_lanfabric_rules && echo 1 || echo 0)"
    print_check "активный wg-quick@${WG_IF}" "$(systemd_wg_active && echo 1 || echo 0)"
    echo

    echo "Конфиги и данные:"
    print_check "$REMOTE_DIR" "$(path_exists "$REMOTE_DIR" && echo 1 || echo 0)"
    print_check "$BACKEND_FILE" "$(path_exists "$BACKEND_FILE" && echo 1 || echo 0)"
    print_check "$WG_DIR" "$(path_exists "$WG_DIR" && echo 1 || echo 0)"
    print_check "$SUDOERS_FILE" "$(path_exists "$SUDOERS_FILE" && echo 1 || echo 0)"
    print_check "$SYSCTL_FILE" "$(path_exists "$SYSCTL_FILE" && echo 1 || echo 0)"
    echo

    local family
    case "$backend" in
        awg)
            family="amnezia"
            ;;
        wg)
            family="wireguard"
            ;;
        *)
            if [ "$awg_installed" = "1" ]; then
                family="amnezia"
            elif [ "$wg_installed" = "1" ]; then
                family="wireguard"
            else
                family="unknown"
            fi
            ;;
    esac

    local state

    if [ "$runtime_present" = "0" ] && [ "$package_present" = "0" ] && [ "$config_present" = "0" ]; then
        state="удалено полностью"
    elif [ "$runtime_present" = "0" ] && [ "$package_present" = "0" ] && [ "$config_present" = "1" ]; then
        if [ "$family" = "amnezia" ]; then
            state="удалено но остались конфиги (amnezia)"
        elif [ "$family" = "wireguard" ]; then
            state="удалено но остались конфиги (wireguard)"
        else
            state="удалено но остались конфиги (backend неизвестен)"
        fi
    elif [ "$runtime_present" = "1" ] && [ "$package_present" = "1" ]; then
        if [ "$family" = "amnezia" ]; then
            state="не удалено (amnezia)"
        elif [ "$family" = "wireguard" ]; then
            state="не удалено (wireguard)"
        else
            state="не удалено (backend неизвестен)"
        fi
    else
        if [ "$family" = "amnezia" ]; then
            state="удалено частично (amnezia)"
        elif [ "$family" = "wireguard" ]; then
            state="удалено частично (wireguard)"
        else
            state="удалено частично (backend неизвестен)"
        fi
    fi

    echo "Итог: ${state}"

    case "$state" in
        "удалено полностью")
            exit 0
            ;;
        "удалено но остались конфиги"*)
            exit 2
            ;;
        "удалено частично"*)
            exit 3
            ;;
        "не удалено"*)
            exit 4
            ;;
        *)
            exit 5
            ;;
    esac
}

main "$@"