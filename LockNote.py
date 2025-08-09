import os
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QMenu, QMenuBar, QFileDialog,
    QMessageBox, QStatusBar, QDialog, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QHBoxLayout
)
from PySide6.QtCore import Qt
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys

extension = ".locked"
password_is_required = False


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

        # Text area
        self.text_area = QTextEdit(self)
        self.setCentralWidget(self.text_area)
        self.text_area.textChanged.connect(self.on_modified)

        # Menu
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("File")

        file_menu.addAction("New", self.new_file, "Ctrl+N")
        file_menu.addAction("Open...", self.open_file, "Ctrl+O")
        file_menu.addAction("Save", self.save_file, "Ctrl+S")
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def create_data_dir(self):
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

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
            self.save_as()

    def save_as(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save As", self.data_dir, "Locked Files (*.locked);;All Files (*)"
        )
        if file_path:
            dialog = PasswordDialog(require_password=password_is_required, parent=self)
            if dialog.exec() == QDialog.Accepted and dialog.password:
                try:
                    content = self.text_area.toPlainText().rstrip() + "\n"
                    plaintext_bytes = content.encode('utf-8')
                    encrypted_data = encrypt_bytes(dialog.password, plaintext_bytes)
                    with open(file_path, 'wb') as f:
                        f.write(encrypted_data)
                    self.current_file = file_path
                    self.encryption_password = dialog.password
                    self.is_modified = False
                    self.update_title()
                    self.status_bar.showMessage(f"Encrypted and saved: {os.path.basename(file_path)}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Could not encrypt and save:\n{str(e)}")

    def closeEvent(self, event):
        if self.prompt_save():
            event.accept()
        else:
            event.ignore()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LockNote()
    window.show()
    sys.exit(app.exec())
