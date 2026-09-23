#!/usr/bin/env python3
"""Одноразовая лаборатория AWG: ключи и конфиги остаются вне журналов."""
import pathlib
import subprocess
import tempfile
import time

IMAGE = "lanfabric-awg-probe:local"
NETWORK = "lf-probe-underlay"
OUTSIDE = "lf-probe-outside"
NAMES = ("lf-probe-gateway", "lf-probe-a", "lf-probe-b", "lf-probe-http")


def run(*args, check=True, timeout=30):
    return subprocess.run(args, check=check, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout)


def docker(*args, **kwargs):
    return run("docker", *args, **kwargs)


def probe(label, args, expected=True):
    for _ in range(8 if expected else 1):
        result = docker("exec", *args, check=False, timeout=8)
        if (result.returncode == 0) == expected:
            print(f"PASS: {label}", flush=True)
            return
        time.sleep(1)
    raise AssertionError(f"FAIL: {label}; exit={result.returncode}; stderr={result.stderr[-250:]}")


def main():
    for name in NAMES:
        docker("rm", "-f", name, check=False)
    for name in (NETWORK, OUTSIDE):
        docker("network", "rm", name, check=False)
    with tempfile.TemporaryDirectory(prefix="lf-awg-") as tmp:
        try:
            docker("network", "create", "--subnet", "172.28.77.0/24", NETWORK)
            docker("network", "create", "--subnet", "172.29.77.0/24", "--internal", OUTSIDE)

            keys = {}
            for role in ("gateway", "a", "b"):
                secret = docker("run", "--rm", "--entrypoint", "/usr/local/bin/awg", IMAGE, "genkey").stdout.strip()
                # stdin передаётся напрямую процессу, не попадает в аргументы и журнал.
                public = subprocess.run(["docker", "run", "--rm", "-i", "--entrypoint", "/usr/local/bin/awg",
                                         IMAGE, "pubkey"], input=secret + "\n", text=True,
                                        capture_output=True, check=True, timeout=30).stdout.strip()
                keys[role] = (secret, public)

            specs = {"gateway": ("10.77.0.1/24", 51820), "a": ("10.77.0.2/32", 51821),
                     "b": ("10.77.0.3/32", 51822)}
            for role, (address, port) in specs.items():
                directory = pathlib.Path(tmp, role)
                directory.mkdir(mode=0o700)
                config = ["[Interface]", f"PrivateKey = {keys[role][0]}", f"ListenPort = {port}",
                          "Jc = 4", "Jmin = 40", "Jmax = 70", "S1 = 15", "S2 = 15",
                          "H1 = 111111", "H2 = 222222", "H3 = 333333", "H4 = 444444"]
                if role == "gateway":
                    for peer in ("a", "b"):
                        config += ["", "[Peer]", f"PublicKey = {keys[peer][1]}",
                                   f"AllowedIPs = {specs[peer][0]}"]
                else:
                    config += ["", "[Peer]", f"PublicKey = {keys['gateway'][1]}",
                               "AllowedIPs = 10.77.0.0/24, 172.29.77.2/32",
                               "Endpoint = 172.28.77.2:51820", "PersistentKeepalive = 5"]
                path = directory / "wg0.conf"
                path.write_text("\n".join(config) + "\n")
                path.chmod(0o600)
                name = "lf-probe-" + role
                ip = {"gateway": "2", "a": "3", "b": "4"}[role]
                docker("run", "-d", "--name", name, "--restart", "unless-stopped",
                       "--network", NETWORK, "--ip", f"172.28.77.{ip}",
                       "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                       "--device", "/dev/net/tun",
                       "--sysctl", "net.ipv4.ip_forward=1" if role == "gateway" else "net.ipv4.ip_forward=0",
                       "-v", f"{directory}:/state:ro", "-e", f"ROLE={role}",
                       "-e", f"VPN_ADDRESS={address}", IMAGE)

            docker("network", "connect", "--ip", "172.29.77.1", OUTSIDE, "lf-probe-gateway")
            docker("run", "-d", "--name", "lf-probe-http", "--network", OUTSIDE,
                   "--ip", "172.29.77.2", "--entrypoint", "python3", IMAGE,
                   "-m", "http.server", "8080", "--bind", "172.29.77.2")

            ping = lambda who, ip: ("lf-probe-" + who, "ping", "-n", "-c", "1", "-W", "2", ip)
            probe("клиент A → шлюз", ping("a", "10.77.0.1"))
            probe("клиент B → шлюз", ping("b", "10.77.0.1"))
            probe("A → B", ping("a", "10.77.0.3"))
            probe("B → A", ping("b", "10.77.0.2"))
            http = lambda who: ("lf-probe-" + who, "python3", "-c",
                                "import urllib.request; urllib.request.urlopen('http://172.29.77.2:8080', timeout=2).read()")
            probe("internet=ДА через шлюз", http("a"))
            probe("internet=НЕТ при живом внешнем сервисе", http("b"), expected=False)

            docker("exec", "lf-probe-gateway", "awg", "set", "wg0", "peer", keys["b"][1], "remove")
            probe("блокировка участника B", ping("b", "10.77.0.1"), expected=False)
            docker("exec", "lf-probe-gateway", "awg", "set", "wg0", "peer", keys["b"][1],
                   "allowed-ips", "10.77.0.3/32")
            probe("повторное разрешение B", ping("b", "10.77.0.1"))

            docker("restart", "lf-probe-gateway", timeout=30)
            probe("восстановление после restart", ping("a", "10.77.0.1"))
            docker("exec", "lf-probe-gateway", "sh", "-c", "kill -9 \"$(cat /run/awg-probe.pid)\"")
            time.sleep(2)
            state = docker("inspect", "-f", "{{.RestartCount}}", "lf-probe-gateway").stdout.strip()
            assert int(state) >= 1, "смерть процесса не вызвала перезапуск контейнера"
            probe("восстановление после аварии", ping("a", "10.77.0.1"))
            probe("запрет B после аварии", http("b"), expected=False)
            print("PASS: функциональный тест контейнеров завершён; секреты не сохранены", flush=True)
        finally:
            for name in NAMES:
                docker("rm", "-f", name, check=False)
            for name in (NETWORK, OUTSIDE):
                docker("network", "rm", name, check=False)


if __name__ == "__main__":
    main()
