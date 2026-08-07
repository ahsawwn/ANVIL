import html
import re

from PySide6.QtWidgets import QTextEdit

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


class ConsoleOutput(QTextEdit):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.setPlaceholderText("Nmap output will appear here...")
        self.document().setMaximumBlockCount(10000)

    def append_line(self, text: str, color: str | None = None) -> None:
        clean = strip_ansi(text)
        if color:
            cursor = self.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            cursor.insertHtml(
                f'<span style="color:{html.escape(color)};">{html.escape(clean)}</span><br/>'
            )
            self.setTextCursor(cursor)
        else:
            self.append(clean)
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

    def append_info(self, text: str) -> None:
        self.append_line(f"[*] {text}", "#4fc3f7")

    def append_error(self, text: str) -> None:
        self.append_line(f"[!] {text}", "#ef5350")

    def append_success(self, text: str) -> None:
        self.append_line(f"[+] {text}", "#66bb6a")

    def append_warning(self, text: str) -> None:
        self.append_line(f"[!] {text}", "#ffca28")

    def append_critical(self, text: str) -> None:
        self.append_line(f"[CRITICAL] {text}", "#ff1744")

    def clear_output(self) -> None:
        self.clear()
