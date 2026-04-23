#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__version__ = "0.0.1"

import os
import sys
import json
import subprocess
import argparse

CONFIG_DIR = os.path.expanduser("~/.vpn-admin")

def run(cmd):
    return subprocess.run(cmd, shell=True)

def save_server(name, host, user):
    path = os.path.join(CONFIG_DIR, name)
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "server.json"), "w") as f:
        json.dump({"host": host, "user": user}, f)

def load_server(name):
    with open(os.path.join(CONFIG_DIR, name, "server.json")) as f:
        return json.load(f)

def ssh(name, cmd):
    s = load_server(name)
    return run(f"ssh {s['user']}@{s['host']} '{cmd}'")

def scp(name, local, remote):
    s = load_server(name)
    return run(f"scp {local} {s['user']}@{s['host']}:{remote}")

def init():
    name = input("Имя сервера: ")
    host = input("IP/host: ")
    user = input("SSH user: ")

    save_server(name, host, user)

    print("Копирование скрипта...")
    scp(name, "vsrv-admin.py", "/opt/vpn-admin/vsrv-admin.py")

    print("Инициализация...")
    ssh(name, "python3 /opt/vpn-admin/vsrv-admin.py init")

def add_user(name, username):
    ssh(name, f"python3 /opt/vpn-admin/vsrv-admin.py add-user {username}")
    print("Готово")

def delete_user(name, username):
    ssh(name, f"python3 /opt/vpn-admin/vsrv-admin.py delete-user {username}")

def list_users(name):
    ssh(name, "python3 /opt/vpn-admin/vsrv-admin.py list")

def status(name):
    ssh(name, "python3 /opt/vpn-admin/vsrv-admin.py status")

def main():
    parser = argparse.ArgumentParser(description="Клиент управления VPN")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("init")

    p_add = sub.add_parser("add-user")
    p_add.add_argument("server")
    p_add.add_argument("username")

    p_del = sub.add_parser("delete-user")
    p_del.add_argument("server")
    p_del.add_argument("username")

    p_list = sub.add_parser("list")
    p_list.add_argument("server")

    p_stat = sub.add_parser("status")
    p_stat.add_argument("server")

    sub.add_parser("version")

    args = parser.parse_args()

    if args.cmd == "init":
        init()
    elif args.cmd == "add-user":
        add_user(args.server, args.username)
    elif args.cmd == "delete-user":
        delete_user(args.server, args.username)
    elif args.cmd == "list":
        list_users(args.server)
    elif args.cmd == "status":
        status(args.server)
    elif args.cmd == "version":
        print(__version__)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()