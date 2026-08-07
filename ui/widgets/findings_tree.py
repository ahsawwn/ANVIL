from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QHeaderView, QTreeView

RISK_COLORS = {
    "Critical": QColor("#ff5252"),
    "High": QColor("#ff7043"),
    "Medium": QColor("#ffd740"),
    "Low": QColor("#69f0ae"),
    "Unknown": QColor("#b0bec5"),
}

COLUMNS = ["Port", "Protocol", "Service", "Version", "Criticality", "CVEs"]


class FindingsTree(QTreeView):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._model = QStandardItemModel(self)
        self._model.setHorizontalHeaderLabels(COLUMNS)
        self.setModel(self._model)
        self.setRootIsDecorated(False)
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)
        header = self.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.setColumnWidth(4, 90)

    def _make_item(self, text: str, color: QColor | None = None) -> QStandardItem:
        item = QStandardItem(str(text))
        item.setEditable(False)
        if color is not None:
            item.setForeground(color)
        return item

    def clear(self) -> None:
        self._model.removeRows(0, self._model.rowCount())

    def update_from_report(self, report) -> None:
        self.clear()
        for port in report.open_ports:
            risk = report.highest_risk_for(port)
            color = RISK_COLORS.get(risk, RISK_COLORS["Unknown"])
            vulns = report.vulnerabilities_for(port)
            cves = ", ".join(
                v.cve_id for v in vulns if v.cve_id and v.cve_id != "N/A"
            ) or "—"
            row = [
                self._make_item(port.port_id),
                self._make_item(port.protocol),
                self._make_item(port.service or port.product or "unknown"),
                self._make_item(port.version_text or "—"),
                self._make_item(risk, color),
                self._make_item(cves),
            ]
            if color is not None:
                for item in row[:4]:
                    item.setForeground(color)
            self._model.appendRow(row)
