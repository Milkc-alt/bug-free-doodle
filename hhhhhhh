import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def pad_key(key_str):
    return key_str.encode().ljust(32, b'\0')[:32]


def encrypt_message():
    key = pad_key(key_entry.get())
    message = message_entry.get("1.0", tk.END).strip().encode()

    try:
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, message, None)
        encrypted = base64.b64encode(nonce + ciphertext).decode()

        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, encrypted)
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))


def decrypt_message():
    key = pad_key(key_entry.get())
    encrypted_b64 = message_entry.get("1.0", tk.END).strip()

    try:
        encrypted = base64.b64decode(encrypted_b64)
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(nonce, ciphertext, None).decode()

        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, plaintext)
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))


def encrypt_file():
    key = pad_key(key_entry.get())
    file_path = filedialog.askopenfilename(title="Select File to Encrypt")
    if not file_path:
        return

    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, data, None)

        output_path = file_path + '.enc'
        with open(output_path, 'wb') as f:
            f.write(nonce + ciphertext)

        messagebox.showinfo("Success", f"File encrypted:\n{output_path}")
    except Exception as e:
        messagebox.showerror("File Encryption Error", str(e))


def decrypt_file():
    key = pad_key(key_entry.get())
    file_path = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted files", "*.enc")])
    if not file_path:
        return

    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        nonce = data[:12]
        ciphertext = data[12:]
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(nonce, ciphertext, None)

        output_path = file_path.replace(".enc", ".dec")
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        messagebox.showinfo("Success", f"File decrypted:\n{output_path}")
    except Exception as e:
        messagebox.showerror("File Decryption Error", str(e))


# ----- GUI -----
window = tk.Tk()
window.title("ChaCha20-Poly1305 Tool")
window.geometry("600x500")

tk.Label(window, text="Enter Key:").pack()
key_entry = tk.Entry(window, width=60, show="*")
key_entry.pack(pady=5)

tk.Label(window, text="Message / Ciphertext:").pack()
message_entry = tk.Text(window, height=5, width=70)
message_entry.pack(pady=5)

btn_frame = tk.Frame(window)
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Encrypt Message", command=encrypt_message).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Decrypt Message", command=decrypt_message).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="Encrypt File", command=encrypt_file).grid(row=1, column=0, padx=5, pady=5)
tk.Button(btn_frame, text="Decrypt File", command=decrypt_file).grid(row=1, column=1, padx=5, pady=5)

tk.Label(window, text="Result:").pack()
result_text = tk.Text(window, height=5, width=70)
result_text.pack(pady=5)

window.mainloop()
