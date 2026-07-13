"""Qt 应用入口。"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

from PyQt6.QtCore import QCoreApplication
from PyQt6.QtGui import QFont, QFontDatabase
from PyQt6.QtWidgets import QApplication, QMessageBox

from .gui import MainWindow


def _configure_font(app: QApplication) -> None:
    """Load a CJK-capable font explicitly for consistent Windows rendering."""

    candidates = (
        Path("C:/Windows/Fonts/msyh.ttc"),
        Path("C:/Windows/Fonts/msyhbd.ttc"),
        Path("C:/Windows/Fonts/simhei.ttf"),
    )
    for path in candidates:
        if not path.exists():
            continue
        font_id = QFontDatabase.addApplicationFont(str(path))
        if font_id < 0:
            continue
        families = QFontDatabase.applicationFontFamilies(font_id)
        if families:
            preferred = "Microsoft YaHei UI" if "Microsoft YaHei UI" in families else families[0]
            app.setFont(QFont(preferred, 9))
            return


def main() -> int:
    app = QApplication(sys.argv)
    QCoreApplication.setOrganizationName("SJTU-CourseProject")
    QCoreApplication.setApplicationName("网络嗅探器")
    app.setStyle("Fusion")
    _configure_font(app)

    def report_exception(exc_type, exc_value, exc_traceback) -> None:  # type: ignore[no-untyped-def]
        detail = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        print(detail, file=sys.stderr)
        QMessageBox.critical(None, "未处理异常", f"程序遇到未处理异常：\n{exc_value}")

    sys.excepthook = report_exception
    window = MainWindow()
    window.show()
    return app.exec()


__all__ = ["main"]
