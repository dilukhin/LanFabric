#!/usr/bin/env python3
"""
run_local_checks.py — скрипт запуска локальных проверок LanFabric v0.0.17.

Выполняет:
1. py_compile обоих модулей
2. --version и ключевые --help
3. unittest discovery по tests_local
4. Печать краткого итога

Возвращает ненулевой код при неожиданных failures/errors.
Только стандартная библиотека Python.
"""

import sys
import os
import subprocess
import importlib.util
import traceback

# Путь к корню проекта
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI_PATH = os.path.join(PROJECT_DIR, "vcli-admin.py")
SRV_PATH = os.path.join(PROJECT_DIR, "vsrv-admin.py")
EXPECTED_VERSION = "0.0.17"


def configure_utf8_output():
    """Настраивает собственный вывод runner на UTF-8 в Windows-консоли."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def utf8_subprocess_env():
    """Возвращает окружение для стабильного UTF-8 вывода дочернего Python."""
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def print_header(title):
    width = 60
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def run_py_compile(path, label):
    print(f"  py_compile {label}... ", end="", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=utf8_subprocess_env()
    )
    if result.returncode == 0:
        print("OK")
        return True
    else:
        print("FAIL")
        print(result.stderr or result.stdout)
        return False


def run_module_version(path, label):
    print(f"  --version {label}... ", end="", flush=True)
    result = subprocess.run(
        [sys.executable, path, "--version"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=utf8_subprocess_env()
    )
    if result.returncode == 0:
        version = result.stdout.strip()
        if not version:
            print("FAIL: пустой вывод версии")
            return False, None
        print(f"OK: {version}")
        return True, version
    else:
        print("FAIL")
        print(result.stderr or result.stdout)
        return False, None


def run_help(path, *args):
    cmd = [sys.executable, path] + list(args) + ["--help"]
    label = " ".join(args) if args else "main"
    print(f"  --help {label}... ", end="", flush=True)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=utf8_subprocess_env(),
    )
    if result.returncode == 0:
        lines = (result.stdout or result.stderr or "").strip().splitlines()
        if not lines:
            print("FAIL: пустой вывод справки")
            return False
        print(f"OK ({len(lines)} строк)")
        return True
    else:
        print("FAIL")
        print(result.stderr or result.stdout)
        return False


def run_unittest():
    """Запускает unittest discovery по tests_local и возвращает успех."""
    import unittest
    print_header("UNIT TESTS (tests_local)")
    test_dir = os.path.dirname(os.path.abspath(__file__))

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=test_dir, pattern="test_*.py")
    runner = unittest.TextTestRunner(stream=sys.stdout, verbosity=2)
    result = runner.run(suite)

    print()
    print(f"  Tests run: {result.testsRun}")
    print(f"  Failures:  {len(result.failures)}")
    print(f"  Errors:    {len(result.errors)}")
    print(f"  Expected failures: {len(result.expectedFailures)}")
    print(f"  Skipped:   {len(result.skipped)}")
    print(f"  Unexpected successes: {len(result.unexpectedSuccesses)}")

    # Успех: нет неожиданных failures и errors
    # expected failures и skipped — OK
    return unittest_result_ok(result)


def unittest_result_ok(result):
    """Проверяет отсутствие неожиданных результатов unittest."""
    return (
        len(result.failures) == 0
        and len(result.errors) == 0
        and len(result.unexpectedSuccesses) == 0
    )


def expected_module_version(module_name):
    """Возвращает ожидаемую строку --version для модуля."""
    return f"{module_name} {EXPECTED_VERSION}"


def main():
    print("LanFabric Local Checks v0.0.17")
    print(f"Python: {sys.version}")
    print(f"Каталог проекта: {PROJECT_DIR}")

    all_ok = True

    # --- 1. py_compile ---
    print_header("STATIC CHECKS (py_compile)")
    ok1 = run_py_compile(CLI_PATH, "vcli-admin.py")
    ok2 = run_py_compile(SRV_PATH, "vsrv-admin.py")
    if not (ok1 and ok2):
        print("  FAIL: синтаксические ошибки в модулях")
        all_ok = False

    # --- 2. --version ---
    print_header("VERSION CHECK")
    ok3, cli_ver = run_module_version(CLI_PATH, "vcli-admin.py")
    ok4, srv_ver = run_module_version(SRV_PATH, "vsrv-admin.py")
    expected_cli = expected_module_version("vcli-admin")
    expected_srv = expected_module_version("vsrv-admin")
    if not (ok3 and ok4):
        all_ok = False
    if cli_ver and cli_ver != expected_cli:
        print(f"  FAIL: ожидалась версия {EXPECTED_VERSION}, получено: {cli_ver}")
        all_ok = False
    if srv_ver and srv_ver != expected_srv:
        print(f"  FAIL: ожидалась версия {EXPECTED_VERSION}, получено: {srv_ver}")
        all_ok = False

    # --- 3. --help ---
    print_header("HELP CHECKS")
    help_ok = True
    for args_list in [
        (CLI_PATH,),
        (CLI_PATH, "trust"),
        (CLI_PATH, "untrust"),
        (CLI_PATH, "init"),
        (CLI_PATH, "config"),
    ]:
        if not run_help(*args_list):
            help_ok = False
    if not help_ok:
        print("  FAIL: ошибки при --help")
        all_ok = False

    # --- 4. Unit тесты ---
    unittest_ok = run_unittest()
    if not unittest_ok:
        print("  FAIL: найдены неожиданные ошибки в unit-тестах")
        all_ok = False

    # --- Итог ---
    print_header("SUMMARY")
    if all_ok:
        print("  Все локальные проверки пройдены.")
        print("  (expected failures — известные дефекты, не ошибки тестов)")
    else:
        print("  Некоторые проверки не пройдены.")
        print("  См. вывод выше для деталей.")

    return 0 if all_ok else 1


if __name__ == "__main__":
    configure_utf8_output()
    try:
        sys.exit(main())
    except Exception as e:
        print(f"Критическая ошибка: {e}")
        traceback.print_exc()
        sys.exit(2)
