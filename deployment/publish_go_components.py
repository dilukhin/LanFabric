#!/usr/bin/env python3
"""Публикация проверенных компонентов штатным процессом выпуска после master CI."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def api(method, path, data=None, binary=False):
    token = os.environ["GH_COMPONENT_TOKEN"]
    url = path if path.startswith("https://uploads.github.com/") else "https://api.github.com/repos/dilukhin/LanFabric" + path
    body = data if binary else (None if data is None else json.dumps(data).encode())
    request = urllib.request.Request(url, data=body, method=method, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "Content-Type": "application/octet-stream" if binary else "application/json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "LanFabric-components"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if method == "GET" and error.code == 404:
            return None
        raise RuntimeError("Операция выпуска GitHub завершилась ошибкой HTTP " + str(error.code)) from None


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_EVENT_NAME") != "push"
            or os.environ.get("GITHUB_REF") != "refs/heads/master" or os.environ.get("GITHUB_REPOSITORY") != "dilukhin/LanFabric"):
        raise RuntimeError("Публикация компонентов разрешена только после push master в собственном CI")
    srv = runpy.run_path(str(ROOT / "vsrv-admin.py"))
    tag = srv["AWG_GO_RELEASE"]
    files = {}
    for name, expected in srv["AWG_GO_RELEASE_SHA256"].items():
        filename = name + "-linux-amd64"
        data = (ROOT / "ci-dist" / filename).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError("Собранный компонент не соответствует проверенному выпуску")
        files[filename] = data
    sources = (
        "LanFabric AWG Go 3.1, Linux amd64. Go без CGO; awg со статической libc.\n"
        "amneziawg-go, MIT: b5928efb6ca19f0153958460c3d141f04abc5c2e\n"
        "https://github.com/amnezia-vpn/amneziawg-go/tree/b5928efb6ca19f0153958460c3d141f04abc5c2e\n"
        "amneziawg-tools, GPL-2.0: ee0f0a9aa34ff0a0da4b3433b9512781cfe02843\n"
        "https://github.com/amnezia-vpn/amneziawg-tools/tree/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843\n"
        "Сборка и компоновка: deployment/build_go_components.py из коммита ниже.\n"
        "В awg-tools-link-inputs.tar.gz находятся исходники/объектные файлы и сведения о libc для повторной компоновки.\n"
        "Коммит LanFabric: " + os.environ["GITHUB_SHA"] + "\n")
    release = api("GET", "/releases/tags/" + tag)
    if release is None:
        release = api("POST", "/releases", {"tag_name": tag, "target_commitish": os.environ["GITHUB_SHA"],
            "name": "AWG Go 3.1 — компоненты r1", "draft": True, "prerelease": True,
            "body": "Готовые закреплённые компоненты для штатной установки LanFabric. Это предварительная поставка компонентов; серверная и клиентская приёмка LanFabric ещё не завершена.\n\n" + sources})
    if not release["draft"]:
        expected = {name: "sha256:" + hashlib.sha256(data).hexdigest() for name, data in files.items()}
        assets = {asset["name"]: asset.get("digest") for asset in release["assets"]}
        if any(assets.get(name) != digest for name, digest in expected.items()):
            raise RuntimeError("Опубликованный выпуск содержит другие компоненты; перезапись запрещена")
        print("Проверенные компоненты уже опубликованы; выпуск сохранён")
        return
    files["SOURCES.txt"] = sources.encode()
    files["awg-tools-link-inputs.tar.gz"] = (ROOT / "ci-dist/awg-tools-link-inputs.tar.gz").read_bytes()
    existing = {asset["name"]: asset for asset in release["assets"]}
    if set(existing) - set(files):
        raise RuntimeError("В черновике есть неизвестные файлы; публикация остановлена")
    for name, data in files.items():
        if name in existing:
            if existing[name].get("digest") != "sha256:" + hashlib.sha256(data).hexdigest():
                raise RuntimeError("Файл черновика отличается; перезапись запрещена")
            continue
        url = release["upload_url"].split("{", 1)[0] + "?name=" + urllib.parse.quote(name)
        asset = api("POST", url, data, binary=True)
        if asset.get("digest") != "sha256:" + hashlib.sha256(data).hexdigest():
            raise RuntimeError("Контрольная сумма загруженного файла не подтверждена")
    api("PATCH", "/releases/" + str(release["id"]), {"draft": False, "make_latest": "false"})
    print("Проверенные компоненты опубликованы: " + tag)


if __name__ == "__main__":
    main()
