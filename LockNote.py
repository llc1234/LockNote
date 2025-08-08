import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

extension = ".locked"

def encrypt_bytes(password, plaintext_bytes):
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=10)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    return salt + iv + ciphertext

def decrypt_bytes(password, encrypted_bytes):
    salt = encrypted_bytes[:16]
    iv = encrypted_bytes[16:32]
    ciphertext = encrypted_bytes[32:]
    key = PBKDF2(password, salt, dkLen=32, count=10)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext_bytes

class LockNote:
    def __init__(self, root):
        self.root = root
        self.root.geometry("800x600")
        self.current_file = None
        self.encryption_password = None
        self.data_dir = "data"
        self.is_modified = False
        self.create_data_dir()

        self.menu_bar = tk.Menu(root)
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="New", command=self.new_file, accelerator="Ctrl+N")
        self.file_menu.add_command(label="Open...", command=self.open_file, accelerator="Ctrl+O")
        self.file_menu.add_command(label="Save", command=self.save_file, accelerator="Ctrl+S")
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.exit_app)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.root.config(menu=self.menu_bar)

        self.scrollbar = tk.Scrollbar(root)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.text_area = tk.Text(
            root,
            yscrollcommand=self.scrollbar.set,
            wrap=tk.WORD,
            font=("Segoe UI", 10),
            undo=True
        )
        self.text_area.pack(expand=True, fill=tk.BOTH)
        self.scrollbar.config(command=self.text_area.yview)
        self.text_area.bind("<<Modified>>", self.on_modified)

        self.root.bind("<Control-n>", lambda e: self.new_file())
        self.root.bind("<Control-o>", lambda e: self.open_file())
        self.root.bind("<Control-s>", lambda e: self.save_file())

        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)

        self.status_bar = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.update_title()

    def create_data_dir(self):
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

    def on_modified(self, event=None):
        self.is_modified = True
        self.update_title()
        self.text_area.edit_modified(False)

    def update_title(self):
        name = os.path.basename(self.current_file) if self.current_file else "Untitled"
        mod = " *" if self.is_modified else ""
        self.root.title(f"LockNote - {name}{mod}")

    def prompt_save(self):
        if self.is_modified:
            result = messagebox.askyesnocancel("Unsaved Changes", "Do you want to save your changes?")
            if result:  # Yes
                self.save_file()
                return not self.is_modified
            elif result is None:  # Cancel
                return False
        return True

    def new_file(self, event=None):
        if not self.prompt_save():
            return
        self.text_area.delete(1.0, tk.END)
        self.current_file = None
        self.encryption_password = None
        self.is_modified = False
        self.update_title()
        self.status_bar.config(text="New file created")

    def open_file(self, event=None):
        if not self.prompt_save():
            return

        file_path = filedialog.askopenfilename(
            initialdir=self.data_dir,
            title="Open File",
            filetypes=(("Locked Files", "*.locked"), ("All Files", "*.*"))
        )

        if file_path:
            is_locked = file_path.lower().endswith(extension)

            if is_locked:
                password = simpledialog.askstring("Password", "Enter file password:", show="*")
                if not password:
                    return

                try:
                    with open(file_path, 'rb') as f:
                        encrypted_data = f.read()
                    plaintext_bytes = decrypt_bytes(password, encrypted_data)
                    content = plaintext_bytes.decode('utf-8')
                    self.current_file = file_path
                    self.encryption_password = password
                    self.text_area.delete(1.0, tk.END)
                    self.text_area.insert(1.0, content)
                    self.is_modified = False
                    self.update_title()
                    self.status_bar.config(text=f"Opened: {os.path.basename(file_path)}")
                except Exception as e:
                    messagebox.showerror("Decryption Failed", str(e))
            else:
                try:
                    with open(file_path, "r", encoding="utf-8") as file:
                        content = file.read()
                    self.current_file = file_path
                    self.encryption_password = None
                    self.text_area.delete(1.0, tk.END)
                    self.text_area.insert(1.0, content)
                    self.is_modified = False
                    self.update_title()
                    self.status_bar.config(text=f"Opened: {os.path.basename(file_path)}")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not open file:\n{str(e)}")

    def save_file(self, event=None):
        if self.current_file:
            content = self.text_area.get(1.0, tk.END).rstrip() + "\n"
            try:
                if self.encryption_password:
                    plaintext_bytes = content.encode('utf-8')
                    encrypted_data = encrypt_bytes(self.encryption_password, plaintext_bytes)
                    with open(self.current_file, 'wb') as f:
                        f.write(encrypted_data)
                    self.status_bar.config(text=f"Encrypted and saved: {os.path.basename(self.current_file)}")
                else:
                    with open(self.current_file, "w", encoding="utf-8") as file:
                        file.write(content)
                    self.status_bar.config(text=f"Saved: {os.path.basename(self.current_file)}")

                self.is_modified = False
                self.update_title()
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file:\n{str(e)}")
        else:
            self.save_as()

    def save_as(self):
        file_path = filedialog.asksaveasfilename(
            initialdir=self.data_dir,
            title="Save As",
            defaultextension=".locked",
            filetypes=(("Locked Files", "*.locked"), ("All Files", "*.*"))
        )
        if file_path:
            password = simpledialog.askstring("Set Password", "Set a password for this file:", show="*")
            if not password:
                return

            try:
                content = self.text_area.get(1.0, tk.END).rstrip() + "\n"
                plaintext_bytes = content.encode('utf-8')
                encrypted_data = encrypt_bytes(password, plaintext_bytes)
                
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
                
                self.current_file = file_path
                self.encryption_password = password
                self.is_modified = False
                self.update_title()
                self.status_bar.config(text=f"Encrypted and saved: {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not encrypt and save:\n{str(e)}")

    def exit_app(self):
        if self.prompt_save():
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = LockNote(root)
    root.mainloop()
