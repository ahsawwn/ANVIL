#!/usr/bin/env python3
"""Anvil - professional GUI Nmap scanner for Kali Linux."""

import logging
import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from config.settings import DB_PATH, LOG_PATH
from storage.database import Database

QSS_PATH = Path(__file__).resolve().parent / "ui" / "styles" / "dark_theme.qss"


def setup_logging() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_PATH),
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("PySide6").setLevel(logging.WARNING)


def require_root() -> bool:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    print("\033[91m[!] Anvil requires root privileges to run Nmap properly.\033[0m")
    print("    Attempting to relaunch with pkexec...")
    try:
        subprocess.Popen(
            ["pkexec", sys.executable, *sys.argv],
            start_new_session=True,
        )
        print("    Relaunching as root via pkexec. A prompt may appear.")
    except Exception as exc:
        print(f"    Could not relaunch: {exc}")
        print("    Restart the application with: sudo python3 main.py")
    return False


def main() -> int:
    setup_logging()
    if not require_root():
        return 1

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    Database.init_db()

    app = QApplication(sys.argv)
    app.setApplicationName("Anvil")
    app.setOrganizationName("Anvil")

    try:
        app.setStyleSheet(QSS_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        logging.warning("Could not load stylesheet: %s", exc)

    from ui.main_window import MainWindow

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
