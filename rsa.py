from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Generate RSA keys
key = RSA.generate(2048)
public_key = key.publickey()

cipher = PKCS1_OAEP.new(public_key)
decipher = PKCS1_OAEP.new(key)

message = "Hello Priyanka, RSA encryption successful!"
encrypted_msg = cipher.encrypt(message.encode())

encoded = base64.b64encode(encrypted_msg).decode()
print("Encrypted:", encoded)

decoded = base64.b64decode(encoded)
decrypted = decipher.decrypt(decoded).decode()
print("Decrypted:", decrypted)
