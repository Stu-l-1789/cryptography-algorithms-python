import hashlib

text = "Priyanka123"
hash_value = hashlib.sha256(text.encode()).hexdigest()

print("Original text:", text)
print("SHA-256 Hash:", hash_value)
