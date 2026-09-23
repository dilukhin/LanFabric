#!/usr/bin/env bash
set -euo pipefail

# Изолированная гостевая Ubuntu; её ядро измеряется, а не предполагается.
root=$(mktemp -d)
vm_pid=''
cleanup() {
    if [[ -n "$vm_pid" ]]; then kill "$vm_pid" 2>/dev/null || true; wait "$vm_pid" 2>/dev/null || true; fi
    rm -rf "$root"
}
trap cleanup EXIT

sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils ubuntu-cloudimage-keyring gnupg

base=https://cloud-images.ubuntu.com/releases/focal/release
for item in ubuntu-20.04-server-cloudimg-amd64.img SHA256SUMS SHA256SUMS.gpg; do
    timeout 3m curl --fail --location --retry 2 --silent --show-error "$base/$item" -o "$root/$item"
done
gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg \
    "$root/SHA256SUMS.gpg" "$root/SHA256SUMS"
grep -F 'ubuntu-20.04-server-cloudimg-amd64.img' "$root/SHA256SUMS" | \
    (cd "$root" && sha256sum --check)
sha256sum "$root/ubuntu-20.04-server-cloudimg-amd64.img"

cp "$root/ubuntu-20.04-server-cloudimg-amd64.img" "$root/guest.img"
qemu-img resize "$root/guest.img" 12G
ssh-keygen -q -t ed25519 -N '' -f "$root/id"
{
    printf '#cloud-config\nusers:\n  - name: probe\n    groups: [sudo]\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - '
    cat "$root/id.pub"
    printf 'ssh_pwauth: false\n'
} > "$root/user-data"
printf 'instance-id: lf-probe-20260923\nlocal-hostname: lf-probe\n' > "$root/meta-data"
cloud-localds "$root/seed.img" "$root/user-data" "$root/meta-data"

accel=(-accel tcg,thread=multi)
if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then accel=(-enable-kvm); fi
echo "Ускорение QEMU: ${accel[*]}"
qemu-system-x86_64 "${accel[@]}" -m 3072 -smp 2 -nographic -serial none -monitor none \
    -drive "file=$root/guest.img,format=qcow2,if=virtio" \
    -drive "file=$root/seed.img,format=raw,if=virtio,readonly=on" \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \
    -device virtio-net-pci,netdev=net0 > "$root/qemu.log" 2>&1 &
vm_pid=$!
ssh_opts=(-i "$root/id" -p 2222 -o StrictHostKeyChecking=accept-new \
          -o UserKnownHostsFile="$root/known_hosts" -o ConnectTimeout=4 -o BatchMode=yes)
guest() { ssh "${ssh_opts[@]}" probe@127.0.0.1 "$@"; }
ready=0
for _ in {1..90}; do
    if guest 'cloud-init status 2>/dev/null | grep -q "status: done" && echo ready' 2>/dev/null; then ready=1; break; fi
    kill -0 "$vm_pid" || { tail -40 "$root/qemu.log"; exit 1; }
    sleep 4
done
test "$ready" = 1 || { echo 'BLOCKED: гостевая ОС не загрузилась за 6 минут'; exit 1; }

guest 'cat /etc/os-release; uname -r; dpkg --audit; apt-cache policy docker.io containerd runc'
kernel_before=$(guest uname -r)
guest "sudo bash -s" < awg_probe/guest_prepare.sh
kernel_after=$(guest uname -r)
test "$kernel_before" = "$kernel_after" || { echo 'FAIL: загруженное ядро изменилось'; exit 1; }
if [[ "$kernel_after" == 5.4.0-88-generic ]]; then
    echo 'PASS: точное ядро 5.4.0-88-generic'
elif [[ "$kernel_after" == 5.4.* ]]; then
    echo "BLOCKED: точное ядро 5.4.0-88 не воспроизведено; загружено $kernel_after"
else
    echo "BLOCKED: даже семейство 5.4 не воспроизведено; загружено $kernel_after"
fi

timeout 12m docker build --pull -t lanfabric-awg-probe:local awg_probe
set -o pipefail
timeout 5m bash -c "docker save lanfabric-awg-probe:local | gzip -1 | ssh ${ssh_opts[*]} probe@127.0.0.1 'gzip -d | sudo docker load'"
scp -i "$root/id" -P 2222 -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="$root/known_hosts" awg_probe/lab.py probe@127.0.0.1:/var/tmp/lf-awg-lab.py
guest 'sudo timeout 7m python3 /var/tmp/lf-awg-lab.py --preserve'

echo 'Перезагрузка только гостевой ОС'
guest 'sudo reboot' || true
sleep 8
ready=0
for _ in {1..90}; do
    if guest 'systemctl is-active --quiet docker && echo ready' 2>/dev/null; then ready=1; break; fi
    kill -0 "$vm_pid" || { tail -40 "$root/qemu.log"; exit 1; }
    sleep 4
done
test "$ready" = 1 || { echo 'FAIL: Docker не восстановился после загрузки'; exit 1; }
guest 'uname -r; sudo docker version --format "{{.Server.Version}}"; sudo containerd --version; sudo runc --version; sudo dpkg --audit'
guest 'sudo timeout 3m python3 /var/tmp/lf-awg-lab.py --check-boot'
echo 'PASS: гостевой функциональный сценарий и загрузка завершены'
