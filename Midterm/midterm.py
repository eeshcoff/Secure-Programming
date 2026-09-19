
"""
Secure Message Vault
SHA-256 integrity check + AES symmetric encryption

Confidentiality -> AES encryption
Integrity       -> SHA-256 hash comparison
Availability    -> (see write-up: key handling / backup considerations)
"""

import sys
import os
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# ---------- State ----------
# Holding this between menu choices lets you encrypt now, decrypt later,
# and actually prove the round-trip works instead of doing it all in one shot.


state = {
    "key": None,
    "ciphertext": None,
    "iv": None,
    "original_hash": None,
    "is_file": False,
    "file_name": None,
}

# ---------- Core operations (fill these in) ----------

def generate_key():

    key = os.urandom(32)  # 256-bit key for AES-256
    return key



def hash_input(data):

    if isinstance(data, str):
        data = data.encode("utf-8")  # Convert string to bytes for hashing

    fingerprint = hashlib.sha256(data).hexdigest()

    return fingerprint



def encrypt_input(data, key):

    if isinstance(data, str):
        data = data.encode("utf-8")

    iv = os.urandom(16)  # AES block size is 16 bytes

    padder = padding.PKCS7(128).padder()  # Block size in bits
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext, iv


def decrypt_input(ciphertext, key, iv=None):

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def verify_integrity(original_hash, recomputed_hash):
    """
    Compare the original hash to a freshly computed one.
    Returns True if they match, False if the data was corrupted/tampered with.
    """
    return original_hash == recomputed_hash

def read_file_contents(filepath):

    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return None

    with open(filepath, "rb") as f:
        return f.read()


# ---------- Menu actions ----------

def process_new_message():
    """Take input, hash it, encrypt it, and stash everything in `state`."""
    choice = input("Encrypt a message or a file? (m/f): ").strip().lower()

    if choice == "f":
        filepath = input("Enter the path to the file: ").strip().strip('"').strip("'")
        data = read_file_contents(filepath)
        if data is None:
            return
        state["is_file"] = True
        state["file_name"] = os.path.basename(filepath)
    else:
        data = input("Enter a message to encrypt: ").strip()
        state["is_file"] = False
        state["file_name"] = None

    key = generate_key()
    ciphertext, iv = encrypt_input(data, key)

    # Store the results in the state
    state["key"] = key
    state["ciphertext"] = ciphertext
    state["iv"] = iv
    state["original_hash"] = hash_input(data)

    print(f"\nEncrypted and stored.")
    print(f"Original SHA-256 hash : {state['original_hash']}")
    print(f"\nCiphertext (hex)      :\n{ciphertext.hex()}\n")
    print(f"IV (hex)              : {iv.hex()}")
    print(f"Key (hex)             : {key.hex()} (keep this secret!)")



def decrypt_and_verify():
    """Decrypt what's in `state`, re-hash the result, and check it matches."""

    if not state["ciphertext"] or not state["key"] or not state["iv"]:
        print("No message has been encrypted yet. Please encrypt a message first.")
        return
    try:
        decrypted_data = decrypt_input(state["ciphertext"], state["key"], state["iv"])
    except ValueError:
        print("Integrity check failed: ciphertext is corrupted or was tampered with (could not decrypt).")
        return

    recomputed_hash = hash_input(decrypted_data)
    passed_integrity = verify_integrity(state["original_hash"], recomputed_hash)

    print()

    if state["is_file"]:
        out_path = f"decrypted_{state['file_name']}"
        with open(out_path, "wb") as f:
            f.write(decrypted_data)
        print(f"Decrypted file written to: {out_path}")
    else:
        print(f"Decrypted message: {decrypted_data.decode('utf-8')}")

    print(f"\nOriginal SHA-256 hash   : {state['original_hash']}")
    print(f"Recomputed SHA-256 hash : {recomputed_hash}\n\n")

    if passed_integrity:
        print("Integrity check passed: the decrypted data matches the original.")
    else:
        print("Integrity check failed: the decrypted data does NOT match the original.")

# ---------- Menu ----------

def print_menu():
    print("\n=== Secure Message Vault ===")
    print("1. Enter a new message/file (hash + encrypt)")
    print("2. Decrypt last message and verify integrity")
    print("3. Exit")


def main():
    while True:
        print_menu()
        choice = input("Select an option: ").strip()

        if choice == "1":
            process_new_message()
        elif choice == "2":
            decrypt_and_verify()
        elif choice == "3":
            print("Goodbye!")
            sys.exit(0)
        else:
            print("Invalid option, try again.")


if __name__ == "__main__":
    main()