# Caesar Cipher for Symmetric Encryption

def caesar_encrypt(message, shift):
    result = ""
    for char in message:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + shift) % 26
            result += chr(shifted + base)
        else:
            result += char
    return result

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# the magic

key = 5
message = "shh this is a secret"

print("Key: (shift amount):", key)
print("Original message:", message)

ciphertext = caesar_encrypt(message, key)
print("Encrypted:", ciphertext)

decrypted = caesar_decrypt(ciphertext, key)
print("Decrypted:", decrypted)