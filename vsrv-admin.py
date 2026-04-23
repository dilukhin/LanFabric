#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__version__ = "0.0.1"

import os
import sys
import json
import subprocess
import argparse
import datetime
import shutil

BASE_DIR = "/opt/vpn-admin"
USERS_DIR = os.path.join(BASE_DIR, "users")
LOG_FILE = os.path.join(BASE_DIR, "vpn-admin.log")
WG_CONF = "/etc/wireguard/wg0.conf"
WG_INTERFACE = "wg0"
NETWORK = "10.10.0.0/24"
SERVER_IP = "10.10.0.1"
RESERVED_IPS = set(range(1, 11))

def log(msg):
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} {msg}\n")

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def ensure_dirs():
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(USERS_DIR, exist_ok=True)

def generate_keypair():
    priv = run("wg genkey").stdout.strip()
    pub = subprocess.run(f"echo {priv} | wg pubkey", shell=True, capture_output=True, text=True).stdout.strip()
    return priv, pub

def load_users():
    users = {}
    if not os.path.exists(USERS_DIR):
        return users
    for u in os.listdir(USERS_DIR):
        path = os.path.join(USERS_DIR, u, "user.json")
        if os.path.exists(path):
            with open(path) as f:
                users[u] = json.load(f)
    return users

def save_user(user):
    path = os.path.join(USERS_DIR, user["username"])
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "user.json"), "w") as f:
        json.dump(user, f, indent=2)

def allocate_ip(users):
    used = {int(u["ip"].split(".")[-1]) for u in users.values()}
    for i in range(2, 255):
        if i in RESERVED_IPS:
            continue
        if i not in used:
            return f"10.10.0.{i}"
    raise Exception("Нет свободных IP")

def wg_add_peer(pubkey, ip):
    run(f"wg set {WG_INTERFACE} peer {pubkey} allowed-ips {ip}/32")

def wg_remove_peer(pubkey):
    run(f"wg set {WG_INTERFACE} peer {pubkey} remove")

def init_server():
    ensure_dirs()
    log("Инициализация сервера")

    if os.path.exists(WG_CONF):
        print("WireGuard уже настроен")
        return

    run("apt update")
    run("apt install -y wireguard iptables-persistent")

    priv, pub = generate_keypair()

    with open(WG_CONF, "w") as f:
        f.write(f"""[Interface]
Address = {SERVER_IP}/24
ListenPort = 51820
PrivateKey = {priv}
""")

    run("sysctl -w net.ipv4.ip_forward=1")
    run(f"wg-quick up {WG_INTERFACE}")
    run(f"systemctl enable wg-quick@{WG_INTERFACE}")

    setup_logrotate()

    print("Сервер инициализирован")
    log("Сервер инициализирован")

def setup_logrotate():
    conf = f"""{LOG_FILE} {{
    daily
    rotate 180
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}}
"""
    with open("/etc/logrotate.d/vpn-admin", "w") as f:
        f.write(conf)

def status():
    res = run(f"wg show {WG_INTERFACE}")
    print(res.stdout)

def health():
    print("Проверка состояния...")
    status()
    run("ip a show wg0")

def add_user(username):
    users = load_users()
    if username in users:
        print("Пользователь уже существует")
        return

    ip = allocate_ip(users)
    priv, pub = generate_keypair()

    user = {
        "username": username,
        "ip": ip,
        "pubkey": pub,
        "enabled": True,
        "internet": False
    }

    save_user(user)
    wg_add_peer(pub, ip)

    with open(os.path.join(USERS_DIR, username, "client.conf"), "w") as f:
        f.write(f"""[Interface]
PrivateKey = {priv}
Address = {ip}/24

[Peer]
PublicKey = {get_server_pub()}
Endpoint = SERVER_IP:51820
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
""")

    log(f"Добавлен пользователь {username}")
    print(f"Пользователь {username} создан")

def get_server_pub():
    return run("wg show wg0 public-key").stdout.strip()

def delete_user(username):
    users = load_users()
    if username not in users:
        print("Нет такого пользователя")
        return

    confirm = input("Введите имя пользователя для подтверждения: ")
    if confirm != username:
        print("Отмена")
        return

    wg_remove_peer(users[username]["pubkey"])
    shutil.rmtree(os.path.join(USERS_DIR, username))
    log(f"Удален пользователь {username}")
    print("Удалено")

def block_user(username):
    users = load_users()
    if username not in users:
        return
    wg_remove_peer(users[username]["pubkey"])
    users[username]["enabled"] = False
    save_user(users[username])
    log(f"Заблокирован {username}")

def list_users():
    users = load_users()
    for u in users.values():
        print(u["username"], u["ip"], "ENABLED" if u["enabled"] else "BLOCKED")

def main():
    parser = argparse.ArgumentParser(description="Управление VPN сервером")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("init")
    sub.add_parser("status")
    sub.add_parser("health")
    sub.add_parser("list")

    p_add = sub.add_parser("add-user")
    p_add.add_argument("username")

    p_del = sub.add_parser("delete-user")
    p_del.add_argument("username")

    p_blk = sub.add_parser("block-user")
    p_blk.add_argument("username")

    sub.add_parser("version")

    args = parser.parse_args()

    if args.cmd == "init":
        init_server()
    elif args.cmd == "status":
        status()
    elif args.cmd == "health":
        health()
    elif args.cmd == "add-user":
        add_user(args.username)
    elif args.cmd == "delete-user":
        delete_user(args.username)
    elif args.cmd == "block-user":
        block_user(args.username)
    elif args.cmd == "list":
        list_users()
    elif args.cmd == "version":
        print(__version__)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()