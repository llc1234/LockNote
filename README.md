# 🔐 LockNote

LockNote is a simple and secure note editor built with Python and Tkinter that allows you to encrypt your notes using AES-256 encryption (CBC mode) with a password. It's perfect for storing sensitive information locally and safely, all in a familiar text editor format.

![screenshot](https://github.com/llc1234/LockNote/raw/main/screenshot.png) <!-- Optional: Replace with actual screenshot -->

---

## ✨ Features

- 📝 Create, edit, and save plain or encrypted text notes.
- 🔒 AES-256 encryption using password-based key derivation (PBKDF2).
- 🧂 Secure encryption with random salt and IV.
- 💡 Intuitive and lightweight GUI using Tkinter.
- 🗂️ Auto-saves in a dedicated `data/` folder.

---

## 📦 Requirements

- Python 3.6+
- Dependencies:
  - `pycryptodome`
  - `tkinter` (usually comes pre-installed with Python)

Install dependencies with pip:

```bash
pip install pycryptodome
