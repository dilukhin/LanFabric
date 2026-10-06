"""Публикация компонентов запрещена из PR и при несовпадении готовых файлов."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("go_publication", ROOT / "deployment/publish_go_components.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class PublicationTests(unittest.TestCase):
    def test_pull_request_cannot_publish(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request"}, clear=True), \
                patch.object(release, "api") as api:
            with self.assertRaises(RuntimeError):
                release.main()
            api.assert_not_called()

    def test_changed_binary_cannot_create_or_overwrite_release(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "ci-dist").mkdir()
            (root / "ci-dist/amneziawg-go-linux-amd64").write_bytes(b"changed")
            env = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/master",
                   "GITHUB_REPOSITORY": "dilukhin/LanFabric", "GITHUB_SHA": "1" * 40}
            with patch.dict(os.environ, env, clear=True), patch.object(release, "ROOT", root), \
                    patch.object(release.runpy, "run_path", return_value={"AWG_GO_RELEASE": "test", "AWG_GO_RELEASE_SHA256": {"amneziawg-go": "0" * 64}}), \
                    patch.object(release, "api") as api:
                with self.assertRaises(RuntimeError):
                    release.main()
                api.assert_not_called()
