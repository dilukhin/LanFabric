#!/usr/bin/env python3
"""Сборка готовых Go/tools в CI; пользователь на VPS этот файл не запускает."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import runpy
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def run(argv, cwd, env=None):
    subprocess.run(argv, cwd=cwd, env=env, check=True, timeout=300)


def main():
    out = ROOT / "ci-dist"
    out.mkdir(exist_ok=True)
    go = ROOT / "ci-src/go"
    tools = ROOT / "ci-src/tools/src"
    env = os.environ.copy()
    env.update(CGO_ENABLED="0", GOOS="linux", GOARCH="amd64", GOTOOLCHAIN="local", GOAMD64="v1")
    cenv = os.environ.copy()
    cenv.update(CFLAGS="-O2 -ffile-prefix-map=" + str(tools) + "=.",
                LDFLAGS="-static -Wl,--build-id=none", SOURCE_DATE_EPOCH="0")
    previous = None
    for attempt in range(2):
        run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=",
             "-o", str(out / "amneziawg-go-linux-amd64"), "."], go, env)
        run(["make", "clean"], tools, cenv)
        run(["make", "-j2", "CC=gcc", "WIREGUARD_TOOLS_VERSION=3.1-pinned", "wg"], tools, cenv)
        shutil.copyfile(tools / "wg", out / "awg-linux-amd64")
        hashes = {}
        for name in ("amneziawg-go-linux-amd64", "awg-linux-amd64"):
            path = out / name
            path.chmod(0o755)
            program_headers = subprocess.check_output(["readelf", "-l", str(path)], text=True)
            if "INTERP" in program_headers:
                raise RuntimeError("Компонент требует динамический загрузчик")
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if previous is not None and previous != hashes:
            raise RuntimeError("Повторная сборка дала другие контрольные суммы")
        previous = hashes
    for name, value in sorted(hashes.items()):
        print("COMPONENT_SHA256 " + name + " " + value, flush=True)
    srv = runpy.run_path(str(ROOT / "vsrv-admin.py"))
    for name, expected in srv["AWG_GO_RELEASE_SHA256"].items():
        if hashes[name + "-linux-amd64"] != expected:
            raise RuntimeError("Сборка отличается от закреплённого компонента")
    # Объектные файлы позволяют повторную компоновку статической управляющей утилиты.
    metadata = out / "LINKING.txt"
    compiler = subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0]
    libc = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", "libc6-dev"], text=True)
    metadata.write_text("gcc *.o -static -o awg\n" + compiler + "\nlibc6-dev=" + libc +
                        "\nИсходники libc: https://launchpad.net/ubuntu/+source/glibc/" + libc + "\n")
    with tarfile.open(out / "awg-tools-link-inputs.tar.gz", "w:gz") as archive:
        archive.add(metadata, arcname="LINKING.txt")
        for path in sorted((ROOT / "ci-src/tools").rglob("*")):
            if path.is_file() and ".git" not in path.relative_to(ROOT / "ci-src/tools").parts and path.name != "wg":
                archive.add(path, arcname="amneziawg-tools/" + str(path.relative_to(ROOT / "ci-src/tools")))
    # Существующее испытание службы использует те же готовые компоненты.
    shutil.copyfile(out / "amneziawg-go-linux-amd64", go / "amneziawg-go")
    shutil.copyfile(out / "awg-linux-amd64", tools / "wg")


if __name__ == "__main__":
    main()
