import sys
from PyQt6.QtWidgets import QApplication, QDialog
from PyQt6.QtGui import QPalette, QColor
from ui.main_window import MainWindow, _BG, _TEXT, _SURFACE, _BORDER
from ui.mode_dialog import ModeDialog


def _apply_dark_palette(app: QApplication):
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window,          QColor(_BG))
    pal.setColor(QPalette.ColorRole.WindowText,      QColor(_TEXT))
    pal.setColor(QPalette.ColorRole.Base,            QColor(_SURFACE))
    pal.setColor(QPalette.ColorRole.AlternateBase,   QColor(_BG))
    pal.setColor(QPalette.ColorRole.Text,            QColor(_TEXT))
    pal.setColor(QPalette.ColorRole.Button,          QColor(_SURFACE))
    pal.setColor(QPalette.ColorRole.ButtonText,      QColor(_TEXT))
    pal.setColor(QPalette.ColorRole.Highlight,       QColor(_BORDER))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(_TEXT))
    app.setPalette(pal)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    _apply_dark_palette(app)

    dlg = ModeDialog()
    if dlg.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    window = MainWindow(start_mode=dlg.mode)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()