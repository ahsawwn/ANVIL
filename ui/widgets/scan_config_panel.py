from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.scanner import ScanProfile

PROFILE_ORDER = [ScanProfile.QUICK, ScanProfile.FULL, ScanProfile.STEALTH, ScanProfile.UDP]


class ScanConfigPanel(QWidget):
    start_requested = Signal(str, object, bool, str)
    stop_requested = Signal()
    renew_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        top_row.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. 192.168.1.1 or 10.0.0.0/24")
        self.target_input.setMinimumWidth(240)
        top_row.addWidget(self.target_input, stretch=3)

        top_row.addWidget(QLabel("Profile:"))
        self.profile_combo = QComboBox()
        for profile in PROFILE_ORDER:
            self.profile_combo.addItem(profile.label, userData=profile)
        top_row.addWidget(self.profile_combo, stretch=2)

        self.tor_checkbox = QCheckBox("Use Tor")
        top_row.addWidget(self.tor_checkbox)

        top_row.addWidget(QLabel("Proxy:"))
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("socks5 127.0.0.1 9050 (optional)")
        self.proxy_input.setMinimumWidth(180)
        top_row.addWidget(self.proxy_input, stretch=2)

        self.renew_button = QPushButton("Renew Circuit")
        self.renew_button.setToolTip("Send NEWNYM to the Tor control port")
        top_row.addWidget(self.renew_button)

        self.start_button = QPushButton("Start Scan")
        self.start_button.setObjectName("startButton")
        self.start_button.setDefault(True)
        top_row.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.setEnabled(False)
        top_row.addWidget(self.stop_button)

        layout.addLayout(top_row)

        self.start_button.clicked.connect(self._emit_start)
        self.stop_button.clicked.connect(self.stop_requested.emit)
        self.renew_button.clicked.connect(self.renew_requested.emit)
        self.target_input.returnPressed.connect(self._emit_start)

    def _emit_start(self) -> None:
        self.start_requested.emit(
            self.target(),
            self.profile(),
            self.tor_checkbox.isChecked(),
            self.proxy_input.text().strip(),
        )

    def target(self) -> str:
        return self.target_input.text().strip()

    def profile(self) -> ScanProfile:
        return self.profile_combo.currentData()

    def use_tor(self) -> bool:
        return self.tor_checkbox.isChecked()

    def custom_proxy(self) -> str:
        return self.proxy_input.text().strip()

    def set_running(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.target_input.setEnabled(not running)
        self.profile_combo.setEnabled(not running)
        self.tor_checkbox.setEnabled(not running)
        self.proxy_input.setEnabled(not running)
