import tkinter as tk
import os
import sqlite3
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASTER_FILE = "master.bin"
DB_FILE = "Vault.db"
PBKDF_ITERATIONS = 310000
MASTER_KEY_LEN = 16
PWD_KEY_LEN = 16

# DB setup
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    username TEXT NOT NULL,
    password_encrypted BLOB NOT NULL,
    nonce BLOB NOT NULL,
    key_encrypted BLOB,
    key_nonce BLOB,
    UNIQUE(domain, username)
)
""")
conn.commit()

#Class

class PasswordEntry:
    def __init__(self, domain, username, password):
        self.domain = domain
        self.username = username
        self.password = password

    def encrypt_password(self, pwd_key):
        """Encrypt the password using its own AES key."""
        aes = AESGCM(pwd_key)
        nonce = os.urandom(12)
        encrypted = aes.encrypt(nonce, self.password.encode(), None)
        return encrypted, nonce


#Functions / Procedures

def create_master_file(password):
    salt = secrets.token_bytes(16)
    stored_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF_ITERATIONS)
    with open(MASTER_FILE, "wb") as f:
        f.write(salt + stored_hash)

def load_master():
    with open(MASTER_FILE, "rb") as f:
        data = f.read()
    return data[:16], data[16:]

def verify_master(password):
    salt, stored_hash = load_master()
    test_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF_ITERATIONS)
    return secrets.compare_digest(test_hash, stored_hash)

def derive_master_key(password):
    salt, _ = load_master()
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF_ITERATIONS)
    return key[:MASTER_KEY_LEN]

def add_entry():
    domain = domain_entry.get().strip()
    username = username_entry.get().strip()
    password = password_entry.get().strip()

    if not domain or not username or not password:
        status_label.config(text="All fields required", fg="red")
        return

    # Generate per-password AES key
    pwd_key = secrets.token_bytes(PWD_KEY_LEN)

    entry = PasswordEntry(domain, username, password)
    encrypted_pwd, pwd_nonce = entry.encrypt_password(pwd_key)

    # Encrypt per-password key using master AES key
    key_nonce = os.urandom(12)
    encrypted_key = master_aesgcm.encrypt(key_nonce, pwd_key, None)

    cursor.execute("""
        INSERT INTO passwords (domain, username, password_encrypted, nonce, key_encrypted, key_nonce)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(domain, username) DO UPDATE SET
            password_encrypted = excluded.password_encrypted,
            nonce = excluded.nonce,
            key_encrypted = excluded.key_encrypted,
            key_nonce = excluded.key_nonce
    """, (domain, username, encrypted_pwd, pwd_nonce, encrypted_key, key_nonce))
    conn.commit()

    status_label.config(text="Saved!", fg="green")
    load_list()

    # CLEAR THE TEXTBOXES
    domain_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)


def delete_entry():
    if not listbox.curselection():
        show_status.config(text="Select an entry to delete", fg="red")
        return

    item = listbox.get(listbox.curselection()[0])
    domain = item.split(" (")[0]
    username = item.split("(")[1][:-1]

    cursor.execute("DELETE FROM passwords WHERE domain=? AND username=?", (domain, username))
    conn.commit()

    show_status.config(text="Deleted!", fg="green")
    load_list()

def load_list():
    listbox.delete(0, tk.END)
    cursor.execute("SELECT domain, username FROM passwords")
    for domain, username in cursor.fetchall():
        listbox.insert(tk.END, f"{domain} ({username})")

def show_password():
    if not listbox.curselection():
        show_status.config(text="Select an entry", fg="red")
        return

    pwd = show_entry.get()
    if not verify_master(pwd):
        show_status.config(text="Incorrect master password", fg="red")
        return

    master_key = derive_master_key(pwd)
    local_master = AESGCM(master_key)

    item = listbox.get(listbox.curselection()[0])
    domain = item.split(" (")[0]
    username = item.split("(")[1][:-1]

    cursor.execute("""
        SELECT password_encrypted, nonce, key_encrypted, key_nonce
        FROM passwords WHERE domain=? AND username=?
    """, (domain, username))
    enc_pwd, pwd_nonce, enc_key, key_nonce = cursor.fetchone()

    # Decrypt per-password key
    pwd_key = local_master.decrypt(key_nonce, enc_key, None)

    # Decrypt password
    pwd_aes = AESGCM(pwd_key)
    decrypted = pwd_aes.decrypt(pwd_nonce, enc_pwd, None).decode()

    show_status.config(text=f"Password: {decrypted}", fg="green")


#MasterPassUI
root = tk.Tk()
root.title("Fury Password Manager")
root.geometry("1280x720")

login_frame = tk.Frame(root)
main_frame = tk.Frame(root)

def show_main():
    login_frame.pack_forget()
    main_frame.pack(fill="both", expand=True)

def create_master():
    p1 = create_entry.get()
    p2 = confirm_entry.get()
    if not p1 or p1 != p2:
        status_login.config(text="Passwords must match", fg="red")
        return
    create_master_file(p1)
    global master_aesgcm
    master_aesgcm = AESGCM(derive_master_key(p1))
    show_main()

def login():
    pwd = login_entry.get()
    if not verify_master(pwd):
        status_login.config(text="Incorrect master password", fg="red")
        return
    global master_aesgcm
    master_aesgcm = AESGCM(derive_master_key(pwd))
    show_main()

login_frame.pack(fill="both", expand=True)

if not os.path.exists(MASTER_FILE):
    tk.Label(login_frame, text="Create Master Password").pack()
    create_entry = tk.Entry(login_frame, show="*")
    confirm_entry = tk.Entry(login_frame, show="*")
    tk.Label(login_frame, text="Master Password").pack()
    create_entry.pack()
    tk.Label(login_frame, text="Confirm Password").pack()
    confirm_entry.pack()
    tk.Button(login_frame, text="Create", command=create_master).pack()
else:
    tk.Label(login_frame, text="Enter Master Password").pack()
    login_entry = tk.Entry(login_frame, show="*")
    login_entry.pack()
    tk.Button(login_frame, text="Login", command=login).pack()

status_login = tk.Label(login_frame, text="", fg="red")
status_login.pack()


#MainUI

left = tk.Frame(main_frame)
right = tk.Frame(main_frame)
left.pack(side="left", fill="y", padx=40, pady=40)
right.pack(side="right", fill="both", expand=True, padx=40, pady=40)

tk.Label(left, text="Domain").pack()
domain_entry = tk.Entry(left)
domain_entry.pack()

tk.Label(left, text="Username").pack()
username_entry = tk.Entry(left)
username_entry.pack()

tk.Label(left, text="Password").pack()
password_entry = tk.Entry(left, show="*")
password_entry.pack()

status_label = tk.Label(left, text="", fg="red")
status_label.pack()

tk.Button(left, text="Save Password", command=add_entry).pack()

tk.Label(right, text="Stored Passwords").pack()
listbox = tk.Listbox(right, width=100, height=20)
listbox.pack()

tk.Button(right, text="Delete", command=delete_entry).pack(pady=10)

load_list()

tk.Label(right, text="Re-enter Master Password").pack()
show_entry = tk.Entry(right, show="*")
show_entry.pack()

show_status = tk.Label(right, text="", fg="red")
show_status.pack()

tk.Button(right, text="Show Password", command=show_password).pack()

root.mainloop()
conn.close()
