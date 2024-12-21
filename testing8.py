from tkinter import *
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from stegano import lsb
import zlib
import os
from PIL import Image

# Functions for Embedding
def compress_message(message):
    return zlib.compress(message.encode())

def encrypt_message(compressed_message, key):
    cipher_suite = Fernet(key)
    encrypted_message = cipher_suite.encrypt(compressed_message)
    return encrypted_message

def embed_message(cover_image_path, encrypted_message, output_path):
    try:
        stego_image = lsb.hide(cover_image_path, encrypted_message.decode('latin1'))
        stego_image.save(output_path)
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Failed to embed message: {str(e)}")
        return False

def embedding_process():
    if not embed_image_path:
        messagebox.showwarning("Warning", "Please upload a cover image.")
        return

    secret_message = text_box.get("1.0", END).strip()
    if not secret_message:
        messagebox.showwarning("Warning", "Please enter a secret message or upload a document.")
        return

    key = Fernet.generate_key()
    with open("secret.txt", "wb") as key_file:
        key_file.write(key)
    messagebox.showinfo("Info", "Encryption key saved to 'secret.txt'. Please store it securely.")

    compressed_message = compress_message(secret_message)
    encrypted_message = encrypt_message(compressed_message, key)

    output_path = "stego_image.png"
    success = embed_message(embed_image_path, encrypted_message, output_path)
    if success:
        messagebox.showinfo("Success", f"Stego image saved as '{output_path}'.")

def upload_embed_image():
    global embed_image_path
    embed_image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg")])
    if embed_image_path:
        embed_image_label.config(text=f"Image Selected: {os.path.basename(embed_image_path)}")
    else:
        embed_image_label.config(text="No image selected.")

def upload_document():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            text_box.delete("1.0", END)
            text_box.insert(END, file.read())
        doc_label.config(text=f"Document Uploaded: {os.path.basename(file_path)}")
    else:
        doc_label.config(text="No document uploaded.")

# Functions for Extraction
def extract_message(stego_image_path):
    try:
        hidden_message = lsb.reveal(stego_image_path)
        if hidden_message is None:
            messagebox.showerror("Error", "No hidden message found in the image.")
            return None
        return hidden_message.encode('latin1')
    except Exception as e:
        messagebox.showerror("Error", f"Error extracting hidden data: {str(e)}")
        return None

def decrypt_message(encrypted_message, key):
    try:
        cipher_suite = Fernet(key)
        compressed_message = cipher_suite.decrypt(encrypted_message)
        return zlib.decompress(compressed_message).decode()
    except Exception as e:
        messagebox.showerror("Error", f"Error decrypting the message: {str(e)}")
        return None

def perform_extraction():
    if not stego_image_path:
        messagebox.showwarning("Warning", "Please upload a stego image.")
        return

    if not key_path:
        messagebox.showwarning("Warning", "Please upload the encryption key.")
        return

    try:
        with open(key_path, "rb") as key_file:
            key = key_file.read()
        Fernet(key)
    except Exception as e:
        messagebox.showerror("Error", f"Invalid encryption key: {e}")
        return

    encrypted_message = extract_message(stego_image_path)
    if encrypted_message is None:
        return

    secret_message = decrypt_message(encrypted_message, key)
    if secret_message:
        messagebox.showinfo("Success", f"Secret Message: {secret_message}")

def upload_stego_image():
    global stego_image_path
    stego_image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg")])
    if stego_image_path:
        stego_image_label.config(text=f"Stego Image Selected: {os.path.basename(stego_image_path)}")
    else:
        stego_image_label.config(text="No stego image selected.")

def upload_encryption_key():
    global key_path
    key_path = filedialog.askopenfilename(filetypes=[("Key files", "*.txt;*.key")])
    if key_path:
        key_label.config(text=f"Key File Selected: {os.path.basename(key_path)}")
    else:
        key_label.config(text="No key file selected.")

# Initialize the Tkinter GUI
root = Tk()
root.title("Image Steganography - Embed & Extract")
root.geometry("800x600")
root.config(bg="#f5f5f5")

# Global variables to store paths
embed_image_path = ""
stego_image_path = ""
key_path = ""

# Title
title_label = Label(root, text="Image Steganography", font=("Arial", 20, "bold"), bg="#f5f5f5", fg="#333")
title_label.pack(pady=10)

# Embedding Section
embed_frame = LabelFrame(root, text="Embedding", font=("Arial", 14), bg="#f5f5f5", fg="#333", padx=10, pady=10)
embed_frame.pack(pady=10, fill="x", padx=20)

embed_image_button = Button(embed_frame, text="Upload Cover Image", command=upload_embed_image, font=("Arial", 12), bg="#007BFF", fg="white")
embed_image_button.grid(row=0, column=0, padx=10)
embed_image_label = Label(embed_frame, text="No image selected.", bg="#f5f5f5", fg="#555", font=("Arial", 12))
embed_image_label.grid(row=0, column=1)

doc_button = Button(embed_frame, text="Upload Document", command=upload_document, font=("Arial", 12), bg="#007BFF", fg="white")
doc_button.grid(row=1, column=0, padx=10, pady=10)
doc_label = Label(embed_frame, text="No document uploaded.", bg="#f5f5f5", fg="#555", font=("Arial", 12))
doc_label.grid(row=1, column=1)

text_box = Text(embed_frame, height=5, width=50, font=("Arial", 12), wrap=WORD, bg="#ffffff", fg="#000")
text_box.grid(row=2, column=0, columnspan=2, pady=10)

embed_button = Button(embed_frame, text="Embed Message", command=embedding_process, font=("Arial", 14), bg="#28A745", fg="white")
embed_button.grid(row=3, column=0, columnspan=2, pady=10)

# Extraction Section
extract_frame = LabelFrame(root, text="Extraction", font=("Arial", 14), bg="#f5f5f5", fg="#333", padx=10, pady=10)
extract_frame.pack(pady=10, fill="x", padx=20)

stego_image_button = Button(extract_frame, text="Upload Stego Image", command=upload_stego_image, font=("Arial", 12), bg="#007BFF", fg="white")
stego_image_button.grid(row=0, column=0, padx=10)
stego_image_label = Label(extract_frame, text="No stego image selected.", bg="#f5f5f5", fg="#555", font=("Arial", 12))
stego_image_label.grid(row=0, column=1)

key_button = Button(extract_frame, text="Upload Encryption Key", command=upload_encryption_key, font=("Arial", 12), bg="#007BFF", fg="white")
key_button.grid(row=1, column=0, padx=10, pady=10)
key_label = Label(extract_frame, text="No key file selected.", bg="#f5f5f5", fg="#555", font=("Arial", 12))
key_label.grid(row=1, column=1)

extract_button = Button(extract_frame, text="Extract Message", command=perform_extraction, font=("Arial", 14), bg="#28A745", fg="white")
extract_button.grid(row=2, column=0, columnspan=2, pady=10)

# Run the GUI
root.mainloop()
