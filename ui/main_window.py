import logging
import threading
from pathlib import Path

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QFileDialog,
    QListView,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from config.settings import APP_NAME, APP_VERSION, VAULT_ROOT
from core.proxy_manager import ProxyManager
from core.scanner import ScanProfile, ScanWorker
from models.scan_result import ScanReport, Vulnerability
from storage.database import Database
from storage.markdown_generator import MarkdownGenerator
from ui.widgets.console_output import ConsoleOutput
from ui.widgets.findings_tree import FindingsTree
from ui.widgets.scan_config_panel import ScanConfigPanel

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    status_message = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} - GUI Nmap Scanner v{APP_VERSION}")
        self.resize(1180, 780)

        self.proxy_manager = ProxyManager()
        self.markdown_generator = MarkdownGenerator()

        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None

        self._build_ui()
        self.status_message.connect(self.console.append_info)
        self.refresh_vault()

    def _build_ui(self) -> None:
        self.tabs = QTabWidget(self)
        self.setCentralWidget(self.tabs)
        self.tabs.addTab(self._build_scanner_tab(), "Scanner")
        self.tabs.addTab(self._build_vault_tab(), "Vault Explorer")
        self.statusBar().showMessage("Ready")

    def _build_scanner_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        self.scan_panel = ScanConfigPanel()
        layout.addWidget(self.scan_panel)

        self.console = ConsoleOutput()
        layout.addWidget(self.console, stretch=2)

        self.findings = FindingsTree()
        layout.addWidget(self.findings, stretch=3)

        self.scan_panel.start_requested.connect(self.start_scan)
        self.scan_panel.stop_requested.connect(self.stop_scan)
        self.scan_panel.renew_requested.connect(self.renew_circuit)
        return tab

    def _build_vault_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.vault_list = QListView()
        self.vault_list_model = QStandardItemModel(self)
        self.vault_list.setModel(self.vault_list_model)
        splitter.addWidget(self.vault_list)

        self.vault_preview = QPlainTextEdit()
        self.vault_preview.setReadOnly(True)
        splitter.addWidget(self.vault_preview)

        splitter.setSizes([320, 820])
        layout.addWidget(splitter, stretch=1)

        self.vault_list.clicked.connect(self._preview_vault_item)
        return tab

    def start_scan(self, target: str, profile: ScanProfile, use_tor: bool, custom_proxy: str) -> None:
        if not target:
            QMessageBox.warning(self, "Missing Target", "Please enter a target IP or CIDR range.")
            return
        if self._worker is not None:
            self.console.append_warning("A scan is already running.")
            return

        if use_tor:
            if not self.proxy_manager.ensure_tor():
                self.console.append_warning("Tor is not running and could not be started. Continuing without anonymity.")
            else:
                self.console.append_success("Tor is running.")
            if not self.proxy_manager.proxychains_bin():
                self.console.append_warning("proxychains4 binary not found. Scan will run directly.")
            self.proxy_manager.build_proxychains_conf(custom_proxy or None)

        self.console.clear_output()
        self.findings.clear()
        self.console.append_info(f"Starting {profile.label} scan against {target}")
        self.statusBar().showMessage(f"Scanning {target} ...")

        self._thread = QThread(self)
        self._worker = ScanWorker(target, profile, use_tor, custom_proxy)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.output.connect(self.console.append_line)
        self._worker.finished.connect(self.on_scan_finished)
        self._worker.failed.connect(self.on_scan_failed)
        self._worker.critical_found.connect(self.on_critical_found)
        self._worker.finished.connect(self._cleanup_worker)
        self._worker.failed.connect(self._cleanup_worker)

        self.scan_panel.set_running(True)
        self._thread.start()

    def stop_scan(self) -> None:
        if self._worker is not None:
            self.console.append_warning("Stopping scan...")
            self._worker.stop()

    def on_scan_finished(self, report: ScanReport) -> None:
        self.console.append_success(f"Scan complete: {report.summary}")
        self.statusBar().showMessage(f"Done: {report.target}")
        self.findings.update_from_report(report)

        Database.log_scan(report)
        self.markdown_generator.generate(report)
        self.refresh_vault()
        self.tabs.setCurrentIndex(0)

        if report.critical_count:
            QMessageBox.warning(
                self,
                "Critical Vulnerabilities",
                f"Found {report.critical_count} critical vulnerability(ies) on {report.target}. "
                "Check the Findings tab and the Obsidian vault.",
            )

    def on_scan_failed(self, message: str) -> None:
        self.console.append_error(message)
        self.statusBar().showMessage("Scan failed")

    def on_critical_found(self, vuln: Vulnerability) -> None:
        self.console.append_critical(f"{vuln.name} on port {vuln.port} ({vuln.service})")
        self._notify_critical(vuln)

    def _notify_critical(self, vuln: Vulnerability) -> None:
        try:
            from plyer import notification

            notification.notify(
                title=f"Anvil: Critical - {vuln.name}",
                message=f"Port {vuln.port} ({vuln.service}) - {vuln.cve_id}",
                timeout=10,
                app_name=APP_NAME,
            )
        except Exception as exc:
            logger.warning("Desktop notification failed: %s", exc)

    def renew_circuit(self) -> None:
        def _run() -> None:
            ok, message = self.proxy_manager.renew_circuit()
            self.status_message.emit(message)

        threading.Thread(target=_run, daemon=True).start()

    def refresh_vault(self) -> None:
        files = self.markdown_generator.all_markdown_files()
        display = [f.relative_to(self.markdown_generator.root).as_posix() for f in files]
        self.vault_list_model.clear()
        for name in display:
            self.vault_list_model.appendRow(QStandardItem(name))
        self.vault_preview.setPlainText(f"{len(files)} markdown file(s) in {VAULT_ROOT}")

    def _preview_vault_item(self, index) -> None:
        rel = index.data()
        if not rel:
            return
        path = self.markdown_generator.root / rel
        try:
            self.vault_preview.setPlainText(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Could not read vault file %s: %s", path, exc)
            self.vault_preview.setPlainText(f"Error reading {path}: {exc}")

    def export_scan_history(self) -> None:
        target, _ = QFileDialog.getSaveFileName(self, "Export Scan History", "anvil_history.json", "JSON Files (*.json)")
        if not target:
            return
        try:
            Path(target).write_text(Database.json_export(), encoding="utf-8")
            self.statusBar().showMessage(f"History exported to {target}")
        except Exception as exc:
            self.console.append_error(f"Export failed: {exc}")

    def _cleanup_worker(self) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(5000)
            self._thread.deleteLater()
        if self._worker is not None:
            self._worker.deleteLater()
        self._thread = None
        self._worker = None
        self.scan_panel.set_running(False)
        self.statusBar().showMessage("Idle")

    def closeEvent(self, event) -> None:
        if self._worker is not None:
            self._worker.stop()
            if self._thread is not None:
                self._thread.quit()
                self._thread.wait(5000)
        Database.close()
        event.accept()
