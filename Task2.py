import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

p = int(
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
    "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
    "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
    "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
    "DF1FB2BC2E4A4371", 16)

g = int(
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
    "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
    "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
    "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
    "855E6EEB22B3B2E5", 16)

def diffie_hellman(p, g):

    # Alice does this
    a = os.urandom(16)
    A = pow(g, int.from_bytes(a), p)  # A = g^a mod p
    
    # Bob does this
    b = os.urandom(16)
    B = pow(g, int.from_bytes(b), p)  # B = g^b mod p


    # Mallory changes both A and B to p now
    secret_Alice = pow(p, int.from_bytes(a), p)  # s_Alice = p^a mod p
    secret_Bob = pow(p, int.from_bytes(b), p)    # s_Bob = p^b mod p
    print(a)
    print("\n")
    print(b)
    print("\n")
    print(secret_Alice)
    assert secret_Alice == secret_Bob, "wrong secrets somehow"
    
    k = hashlib.sha256(secret_Alice.to_bytes((secret_Alice.bit_length() + 7) // 8)).digest()[:16]
    
    return k


# share key
symmetric_key = diffie_hellman(p, g)
print(f"Shared symmetric key: {symmetric_key.hex()}")

# Alice makes a message for bob
message_to_bob = b"Hi Bob!"
alice_cipher = AES.new(symmetric_key, AES.MODE_CBC, os.urandom(AES.block_size))
ciphertext_to_bob = alice_cipher.encrypt(pad(message_to_bob, AES.block_size))
print(f"Ciphertext to Bob: {ciphertext_to_bob.hex()}")

# Check Bob decrypts the message
decipher_by_bob = AES.new(symmetric_key, AES.MODE_CBC, alice_cipher.iv)
decrypted_message_by_bob = unpad(decipher_by_bob.decrypt(ciphertext_to_bob), AES.block_size)
print(f"Decrypted message by Bob: {decrypted_message_by_bob.decode('utf-8')}")

# Bob sends a message to Alice
message_to_alice = b"Hi Alice!"
cipher_to_alice = AES.new(symmetric_key, AES.MODE_CBC, os.urandom(AES.block_size))
ciphertext_to_alice = cipher_to_alice.encrypt(pad(message_to_alice, AES.block_size))
print(f"Ciphertext to Alice: {ciphertext_to_alice.hex()}")

# Check Alice decrypts the message
decipher_by_alice = AES.new(symmetric_key, AES.MODE_CBC, cipher_to_alice.iv)
decrypted_message_by_alice = unpad(decipher_by_alice.decrypt(ciphertext_to_alice), AES.block_size)
print(f"Decrypted message by Alice: {decrypted_message_by_alice.decode('utf-8')}")
