import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode

class EncryptionManager:
    def __init__(self, key_size = 256):
        self.key_size = key_size
        self.block_size = 128
        print("initialized")

    def generate_key(self):
        key_bytes = self.key_size // 8
        key = os.urandom(key_bytes)
        print(f"generated encryption key: {self.key_size} bit")
        return key
    
    def generate_iv(self):
        # identical input produce unique outputs
        iv = os.urandom(16)
        return iv
    
    def calculate_hash(self, data):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data.encode('utf-8'))
        hash_value = sha256_hash.hexdigest()
        print(f"SHA-256 hash: {hash_value}")

if __name__ == "__main__":
    manager = EncryptionManager()
    key = manager.generate_key()
    iv = manager.generate_iv()
    test_data = "Hello World"
    hash_value = manager.calculate_hash(test_data)
    print(f"Key length: {len(key)} bytes")
    print(f"IV length: {len(iv)} bytes")
    print(f"Hash: {hash_value}")