import os
import json
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QMenu, QMenuBar, QFileDialog,
    QMessageBox, QStatusBar, QDialog, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QHBoxLayout, QColorDialog, QSpinBox, QWidget, QGridLayout
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QTextCharFormat, QColor, QTextCursor
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys

extension = ".locked"
password_is_required = False

SETTINGS_FILE = "locknote_settings.json"

def encrypt_bytes(password, plaintext_bytes):
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=1_000_000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    return salt + iv + ciphertext

def decrypt_bytes(password, encrypted_bytes):
    salt = encrypted_bytes[:16]
    iv = encrypted_bytes[16:32]
    ciphertext = encrypted_bytes[32:]
    key = PBKDF2(password, salt, dkLen=32, count=1_000_000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext_bytes

class PasswordDialog(QDialog):
    def __init__(self, require_password=True, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Set Password")
        self.password = None
        self.require_password = require_password
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        self.label1 = QLabel("Enter Password:")
        self.entry1 = QLineEdit()
        self.entry1.setEchoMode(QLineEdit.Password)

        self.label2 = QLabel("Confirm Password:")
        self.entry2 = QLineEdit()
        self.entry2.setEchoMode(QLineEdit.Password)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: red;")

        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("OK")
        cancel_btn = QPushButton("Cancel")

        ok_btn.clicked.connect(self.validate)
        cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)

        layout.addWidget(self.label1)
        layout.addWidget(self.entry1)
        layout.addWidget(self.label2)
        layout.addWidget(self.entry2)
        layout.addWidget(self.error_label)
        layout.addLayout(btn_layout)

    def validate(self):
        pw1 = self.entry1.text()
        pw2 = self.entry2.text()
        if not pw1 or not pw2:
            if self.require_password:
                self.error_label.setText("Both fields are required.")
                return
            else:
                self.password = "Pa22word1234"
                self.accept()
        elif pw1 != pw2:
            self.error_label.setText("Passwords do not match.")
        else:
            self.password = pw1
            self.accept()

class FindReplaceDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Find and Replace")
        self.parent = parent
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Find
        find_layout = QHBoxLayout()
        find_label = QLabel("Find:")
        self.find_input = QLineEdit()
        self.find_btn = QPushButton("Find")
        find_layout.addWidget(find_label)
        find_layout.addWidget(self.find_input)
        find_layout.addWidget(self.find_btn)

        # Replace
        replace_layout = QHBoxLayout()
        replace_label = QLabel("Replace:")
        self.replace_input = QLineEdit()
        self.replace_btn = QPushButton("Replace All")
        replace_layout.addWidget(replace_label)
        replace_layout.addWidget(self.replace_input)
        replace_layout.addWidget(self.replace_btn)

        self.result_label = QLabel("")
        self.result_label.setStyleSheet("color: green;")

        layout.addLayout(find_layout)
        layout.addLayout(replace_layout)
        layout.addWidget(self.result_label)

        self.find_btn.clicked.connect(self.find_text)
        self.replace_btn.clicked.connect(self.replace_text)

    def find_text(self):
        text = self.find_input.text()
        if not text:
            self.result_label.setText("Enter text to find.")
            return

        content = self.parent.text_area.toPlainText()
        count = content.count(text)
        if count == 0:
            self.result_label.setText(f"'{text}' not found.")
            return

        # Highlight all occurrences
        self.parent.highlight_text(text)

        self.result_label.setText(f"Found {count} occurrence(s) of '{text}'.")

    def replace_text(self):
        find_text = self.find_input.text()
        replace_text = self.replace_input.text()
        if not find_text:
            self.result_label.setText("Enter text to find.")
            return

        content = self.parent.text_area.toPlainText()
        count = content.count(find_text)
        if count == 0:
            self.result_label.setText(f"'{find_text}' not found.")
            return

        new_content = content.replace(find_text, replace_text)
        self.parent.text_area.setPlainText(new_content)
        self.result_label.setText(f"Replaced {count} occurrence(s) of '{find_text}' with '{replace_text}'.")
        self.parent.is_modified = True
        self.parent.update_title()

class WordColorDialog(QDialog):
    def __init__(self, word_color_map, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Word Color Settings")
        self.word_color_map = word_color_map  # dict of word:str -> color:str
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        self.grid = QGridLayout()

        self.word_edits = []
        self.color_buttons = []

        # Add rows for each word-color pair
        for i, (word, color) in enumerate(self.word_color_map.items()):
            word_edit = QLineEdit(word)
            color_btn = QPushButton()
            color_btn.setStyleSheet(f"background-color: {color};")
            color_btn.clicked.connect(lambda _, b=color_btn: self.choose_color(b))

            self.word_edits.append(word_edit)
            self.color_buttons.append(color_btn)

            self.grid.addWidget(QLabel("Word:"), 0, 0)
            self.grid.addWidget(QLabel("Color:"), 0, 1)
            self.grid.addWidget(word_edit, i + 1, 0)
            self.grid.addWidget(color_btn, i + 1, 1)

        add_word_btn = QPushButton("Add Word")
        add_word_btn.clicked.connect(self.add_word_row)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")

        save_btn.clicked.connect(self.save)
        cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)

        layout.addLayout(self.grid)
        layout.addWidget(add_word_btn)
        layout.addLayout(btn_layout)

    def add_word_row(self):
        row = len(self.word_edits) + 1
        word_edit = QLineEdit()
        color_btn = QPushButton()
        color_btn.setStyleSheet("background-color: #000000;")
        color_btn.clicked.connect(lambda _, b=color_btn: self.choose_color(b))

        self.word_edits.append(word_edit)
        self.color_buttons.append(color_btn)

        self.grid.addWidget(word_edit, row, 0)
        self.grid.addWidget(color_btn, row, 1)

    def choose_color(self, button):
        color = QColorDialog.getColor()
        if color.isValid():
            button.setStyleSheet(f"background-color: {color.name()};")

    def save(self):
        new_map = {}
        for word_edit, color_btn in zip(self.word_edits, self.color_buttons):
            word = word_edit.text().strip()
            if not word:
                continue
            # Extract color from stylesheet background-color property
            style = color_btn.styleSheet()
            # Usually style is like 'background-color: #rrggbb;'
            color = style.split(":")[-1].strip().strip(";")
            new_map[word] = color
        self.word_color_map.clear()
        self.word_color_map.update(new_map)
        self.accept()

class SettingsDialog(QDialog):
    def __init__(self, parent=None, current_settings=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.current_settings = current_settings or {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Theme selection
        self.theme_label = QLabel("Theme:")
        self.theme_light = QPushButton("Light")
        self.theme_dark = QPushButton("Dark")
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(self.theme_light)
        theme_layout.addWidget(self.theme_dark)

        self.theme_light.clicked.connect(lambda: self.set_theme("light"))
        self.theme_dark.clicked.connect(lambda: self.set_theme("dark"))

        # Text size spinner
        size_layout = QHBoxLayout()
        size_label = QLabel("Text Size (4-16):")
        self.size_spin = QSpinBox()
        self.size_spin.setRange(4, 16)
        size_layout.addWidget(size_label)
        size_layout.addWidget(self.size_spin)

        # Buttons
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")

        save_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)

        layout.addWidget(self.theme_label)
        layout.addLayout(theme_layout)
        layout.addLayout(size_layout)
        layout.addLayout(btn_layout)

        # Initialize current values
        theme = self.current_settings.get("theme", "light")
        if theme == "light":
            self.size_spin.setValue(self.current_settings.get("text_size", 12))
        else:
            self.size_spin.setValue(self.current_settings.get("text_size", 12))

    def set_theme(self, theme):
        self.current_settings["theme"] = theme

class LockNote(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LockNote - Untitled")
        self.resize(800, 600)

        self.current_file = None
        self.encryption_password = None
        self.data_dir = "data"
        self.is_modified = False
        self.create_data_dir()

        # Load settings
        self.settings = {
            "theme": "light",
            "text_size": 12,
            "word_colors": {}
        }
        self.load_settings()

        # Text area
        self.text_area = QTextEdit(self)
        self.setCentralWidget(self.text_area)
        self.text_area.textChanged.connect(self.on_modified)
        self.apply_settings()

        # Menu
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("File")
        settings_menu = menu_bar.addMenu("Settings")

        file_menu.addAction("New", self.new_file, "Ctrl+N")
        file_menu.addAction("Open...", self.open_file, "Ctrl+O")
        file_menu.addAction("Save", self.save_file, "Ctrl+S")
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)

        # Settings submenus
        settings_menu.addAction("Change Text Color", self.change_text_color)
        settings_menu.addAction("Change Text Size", self.change_text_size)
        settings_menu.addSeparator()
        settings_menu.addAction("Toggle Theme (Dark/Light)", self.toggle_theme)
        settings_menu.addSeparator()
        settings_menu.addAction("Find and Replace", self.open_find_replace)
        settings_menu.addAction("Word Color Settings", self.open_word_color_settings)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def create_data_dir(self):
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    self.settings.update(loaded)
            except Exception:
                pass

    def save_settings(self):
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            QMessageBox.warning(self, "Settings Save Error", f"Could not save settings:\n{str(e)}")

    def apply_settings(self):
        # Apply theme
        if self.settings.get("theme") == "dark":
            self.setStyleSheet("""
                QTextEdit { background-color: #2b2b2b; color: #e6e6e6; }
                QMainWindow { background-color: #2b2b2b; }
            """)
        else:
            self.setStyleSheet("")

        # Apply text size
        font = self.text_area.font()
        font.setPointSize(self.settings.get("text_size", 12))
        self.text_area.setFont(font)

        # Re-apply word colors if any
        self.highlight_colored_words()

    def on_modified(self):
        self.is_modified = True
        self.update_title()

    def update_title(self):
        name = os.path.basename(self.current_file) if self.current_file else "Untitled"
        mod = " *" if self.is_modified else ""
        self.setWindowTitle(f"LockNote - {name}{mod}")

    def prompt_save(self):
        if self.is_modified:
            reply = QMessageBox.question(
                self, "Unsaved Changes",
                "Do you want to save your changes?",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
            )
            if reply == QMessageBox.Yes:
                self.save_file()
                return not self.is_modified
            elif reply == QMessageBox.Cancel:
                return False
        return True

    def new_file(self):
        if not self.prompt_save():
            return
        self.text_area.clear()
        self.current_file = None
        self.encryption_password = None
        self.is_modified = False
        self.update_title()
        self.status_bar.showMessage("New file created")

    def open_file(self):
        if not self.prompt_save():
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open File", self.data_dir, "Locked Files (*.locked);;All Files (*)"
        )
        if file_path:
            is_locked = file_path.lower().endswith(extension)

            if is_locked:
                from PySide6.QtWidgets import QInputDialog
                password, ok = QInputDialog.getText(self, "Password", "Enter file password:", QLineEdit.Password)
                if not ok:
                    return
                if not password and not password_is_required:
                    password = "Pa22word1234"

                try:
                    with open(file_path, 'rb') as f:
                        encrypted_data = f.read()
                    plaintext_bytes = decrypt_bytes(password, encrypted_data)
                    content = plaintext_bytes.decode('utf-8')
                    self.current_file = file_path
                    self.encryption_password = password
                    self.text_area.setPlainText(content)
                    self.is_modified = False
                    self.update_title()
                    self.status_bar.showMessage(f"Opened: {os.path.basename(file_path)}")
                    self.highlight_colored_words()
                except Exception as e:
                    QMessageBox.critical(self, "Decryption Failed", str(e))
            else:
                try:
                    with open(file_path, "r", encoding="utf-8") as file:
                        content = file.read()
                    self.current_file = file_path
                    self.encryption_password = None
                    self.text_area.setPlainText(content)
                    self.is_modified = False
                    self.update_title()
                    self.status_bar.showMessage(f"Opened: {os.path.basename(file_path)}")
                    self.highlight_colored_words()
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Could not open file:\n{str(e)}")

    def save_file(self):
        if self.current_file:
            content = self.text_area.toPlainText().rstrip() + "\n"
            try:
                if self.encryption_password:
                    plaintext_bytes = content.encode('utf-8')
                    encrypted_data = encrypt_bytes(self.encryption_password, plaintext_bytes)
                    with open(self.current_file, 'wb') as f:
                        f.write(encrypted_data)
                    self.status_bar.showMessage(f"Encrypted and saved: {os.path.basename(self.current_file)}")
                else:
                    with open(self.current_file, "w", encoding="utf-8") as file:
                        file.write(content)
                    self.status_bar.showMessage(f"Saved: {os.path.basename(self.current_file)}")

                self.is_modified = False
                self.update_title()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not save file:\n{str(e)}")
        else:
            self.save_file_as()

    def save_file_as(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save File As", self.data_dir, "Locked Files (*.locked);;All Files (*)"
        )
        if file_path:
            if file_path.lower().endswith(extension):
                if not self.encryption_password:
                    dlg = PasswordDialog(require_password=True, parent=self)
                    if dlg.exec() == QDialog.Accepted:
                        self.encryption_password = dlg.password
                    else:
                        return
            else:
                self.encryption_password = None

            self.current_file = file_path
            self.save_file()

    def change_text_color(self):
        color = QColorDialog.getColor()
        if color.isValid():
            self.text_area.setTextColor(color)

    def change_text_size(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Change Text Size")
        layout = QVBoxLayout(dlg)
        spin = QSpinBox()
        spin.setRange(4, 16)
        spin.setValue(self.settings.get("text_size", 12))
        layout.addWidget(QLabel("Select text size:"))
        layout.addWidget(spin)

        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("OK")
        cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)

        layout.addLayout(btn_layout)

        ok_btn.clicked.connect(dlg.accept)
        cancel_btn.clicked.connect(dlg.reject)

        if dlg.exec() == QDialog.Accepted:
            self.settings["text_size"] = spin.value()
            self.apply_settings()
            self.is_modified = True
            self.update_title()

    def toggle_theme(self):
        self.settings["theme"] = "dark" if self.settings.get("theme") == "light" else "light"
        self.apply_settings()
        self.is_modified = True
        self.update_title()

    def open_find_replace(self):
        dlg = FindReplaceDialog(self)
        dlg.exec()

    def open_word_color_settings(self):
        dlg = WordColorDialog(self.settings["word_colors"], self)
        if dlg.exec() == QDialog.Accepted:
            self.highlight_colored_words()
            self.is_modified = True
            self.update_title()

    def highlight_text(self, text):
        cursor = self.text_area.textCursor()
        fmt = QTextCharFormat()
        fmt.setBackground(QColor("yellow"))

        # Clear previous highlights first
        self.text_area.selectAll()
        clear_fmt = QTextCharFormat()
        clear_fmt.setBackground(Qt.transparent)
        self.text_area.textCursor().mergeCharFormat(clear_fmt)
        cursor.clearSelection()

        # Highlight all occurrences
        pos = 0
        doc = self.text_area.document()
        while True:
            found = doc.find(text, pos)
            if found.isNull():
                break
            cursor = found
            cursor.mergeCharFormat(fmt)
            pos = found.position()

    def highlight_colored_words(self):
        # Clear formatting first
        cursor = self.text_area.textCursor()
        cursor.select(QTextCursor.Document)
        clear_fmt = QTextCharFormat()
        clear_fmt.setForeground(QColor(self.text_area.palette().text().color()))
        clear_fmt.setBackground(Qt.transparent)
        cursor.mergeCharFormat(clear_fmt)

        content = self.text_area.toPlainText()
        doc = self.text_area.document()
        for word, color_str in self.settings.get("word_colors", {}).items():
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(color_str))
            pos = 0
            while True:
                found = doc.find(word, pos)
                if found.isNull():
                    break
                cursor = found
                cursor.mergeCharFormat(fmt)
                pos = found.position()

    def closeEvent(self, event):
        if not self.prompt_save():
            event.ignore()
            return
        self.save_settings()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LockNote()
    window.show()
    sys.exit(app.exec())
