from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    return text[:-ord(text[-1])]

def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(plaintext).encode())
    return base64.b64encode(encrypted_text).decode()

def decrypt(key, encrypted_text):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_text)).decode()
    return unpad(decrypted)

key = get_random_bytes(16)
message = "Hello Priyanka, AES encryption successful!"

encrypted = encrypt(key, message)
decrypted = decrypt(key, encrypted)

print("AES Key:", key)
print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
