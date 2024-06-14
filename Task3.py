import random
from Crypto.Util.number import getPrime, inverse

def generate_keypair(bits):
    e = 65537

    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)

    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    e, n = public_key
    plaintext_int = int.from_bytes(plaintext.encode('utf-8'))
    ciphertext = pow(plaintext_int, e, n)
    return ciphertext

def decrypt(private_key, ciphertext):
    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)
    return plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8)


# gen keys
public_key, private_key = generate_keypair(1024)

# BoB/(ian) encrypts a message for Alice with her public key
message = "Hello, I am Ian"
ciphertext = encrypt(public_key, message)
print(f"Ciphertext: {ciphertext}")

#MALLORY ATTACK - Mallory
k = random.randint(2, public_key[1] - 1)
modified_ciphertext = (k * pow(k, public_key[0], public_key[1]) * ciphertext) % public_key[1]

#Alice decrypts the modified message
decrypted_message = decrypt(private_key, modified_ciphertext)
print(f"Decrypted message: {decrypted_message}")
