#!/usr/bin/env bash
set -euo pipefail

test "$(. /etc/os-release; echo "$VERSION_ID")" = 20.04
before=$(uname -r)
echo "Исходное ядро: $before"
test -z "$(dpkg --audit)"
apt-get update -qq
apt-get -s install docker.io > /tmp/lf-apt-plan
if grep -Eq '^(Remv |Inst (linux-image|linux-modules|.*dkms))' /tmp/lf-apt-plan; then
    echo 'BLOCKED: план установки меняет ядро, DKMS или удаляет пакет'
    grep -E '^(Remv |Inst (linux-image|linux-modules|.*dkms))' /tmp/lf-apt-plan
    exit 1
fi
echo 'План установки Docker без изменения ядра/DKMS/removals'
grep -E '^Inst (docker.io|containerd|runc)' /tmp/lf-apt-plan || true
DEBIAN_FRONTEND=noninteractive timeout 7m apt-get install -y --no-install-recommends docker.io
test "$(uname -r)" = "$before"
test -z "$(dpkg --audit)"
test -c /dev/net/tun || { modprobe tun; test -c /dev/net/tun; }
systemctl is-active --quiet docker
docker version --format '{{.Server.Version}}'
containerd --version
runc --version
echo 'PASS: Docker установлен без upgrade ОС и ядра'
