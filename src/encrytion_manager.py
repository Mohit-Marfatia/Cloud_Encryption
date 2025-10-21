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
        return hash_value

    def encrypt_data(self, plaintext, key):
        print(f"encrypting {len(plaintext)} bytes of data...")

        iv = self.generate_iv()

        original_hash = self.calculate_hash(plaintext)

        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        print(f"padded data to {len(padded_data)} bytes")

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        print(f"encryption done")

        return {
            'ciphertext': b64encode(ciphertext).decode('utf-8'),
            'iv': b64encode(iv).decode('utf-8'),
            'original_hash': original_hash,
            'key_size': self.key_size
        }

    def decrypt_data(self, encrypted_data, key):
        ciphertext = b64decode(encrypted_data['ciphertext'])
        iv = b64decode(encrypted_data['iv'])

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(self.block_size).unpadder()
        plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
        plaintext = plaintext_bytes.decode('utf-8')

        calculated_hash = self.calculate_hash(plaintext)
        integrity_verified = (calculated_hash == encrypted_data['original_hash'])

        if integrity_verified:
            print(f"Integrity verified")
        else:
            print(f"Integrity check Failed")

        print("Decryption completed")

        return plaintext, integrity_verified

if __name__ == "__main__":
    manager = EncryptionManager()
    key = manager.generate_key()

    iv = manager.generate_iv()
    test_data = "Hello World"

    print("\n ENCRYPTION")
    encrypted = manager.encrypt_data(test_data, key)
    print(f"Ciphertext(base64): {encrypted['ciphertext']}")
    print(f"Original hash: {encrypted['original_hash']}")
    
    print("\n DECRYPTION")
    decrypted, verified = manager.decrypt_data(encrypted, key)
    print(f"Decrypted data: {decrypted}")
    print(f"Integrity verified: {verified}")
    
    print("\n VERIFICATION")
    if test_data == decrypted:
        print("Original data matches decrypted data")
    else:
        print("Data mismatch!")