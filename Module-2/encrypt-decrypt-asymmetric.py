#---Asymmetry RSA Formula---

# modulus (prime numbers)
p = 61
q = 53

# Totient
n = p * q
phi = (p - 1) * (q -1)

# Public Exponent
e = 17

# Private Exponent

def mod_inverse(e, phi):
    for d in range(2, phi):
        if (e * d) % phi == 1:
            return d
    raise ValueError("No modular inverse.")

d = mod_inverse(e, phi)

public_key = (e, n)
private_key = (d ,n)
print("Public Key (e, n):", public_key)
print("Private Key (d, n):", private_key)

# encryption

message = "shh this is a secret"
print("Original Message:", message)

ciphertext = [pow(ord(char), e, n) for char in message]
print("Encrypted:", ciphertext)

decrypted = ''.join(chr(pow(c, d, n)) for c in ciphertext)
print("Decrypted:", decrypted)