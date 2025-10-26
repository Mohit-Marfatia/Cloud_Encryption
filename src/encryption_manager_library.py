import json
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
        sha256_hash.update(data)
        hash_value = sha256_hash.hexdigest()
        print(f"SHA-256 hash: {hash_value}")
        return hash_value

    def encrypt_data(self, plaintext, key):
        print(f"encrypting {len(plaintext)} bytes of data...")

        iv = self.generate_iv()

        original_hash = self.calculate_hash(plaintext)

        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
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
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        calculated_hash = self.calculate_hash(plaintext)
        integrity_verified = (calculated_hash == encrypted_data['original_hash'])

        if integrity_verified:
            print(f"Integrity verified")
        else:
            print(f"Integrity check Failed")

        print("Decryption completed")

        return plaintext, integrity_verified
    
    def encrypt_file(self, file_path, key):
        print(f"Encrypting file : {file_path}")

        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        print(f"File size : {len(file_data)} bytes")

        encrypted_data = self.encrypt_data(file_data, key)
        encrypted_data['original_filename'] = os.path.basename(file_path)
        encrypted_data['original_size'] = len(file_data)

        # with open("./files/encrypted_test_file", 'wb') as f:
        #     json.dump(encrypted_data, f, indent=4)

        print("File encryption completed")

        return encrypted_data

    def decrypt_file(self, encrypted_data, key, output_path):
        print(f"\nDecrypting file to: {output_path}")

        plaintext, integrity_verified = self.decrypt_data(encrypted_data, key)

        with open(output_path, 'wb') as f:
            f.write(plaintext)

        print(f"File writtern: {len(plaintext)} bytes")

        return integrity_verified

if __name__ == "__main__":
    manager = EncryptionManager()
    key = manager.generate_key()

    # iv = manager.generate_iv()
    test_content = b"This is a test file with sensitive data!\nLine 2\nLine 3"
    test_file = "files/test_file.txt"

    print("\nENCRYPTION")
    encrypted = manager.encrypt_file(test_file, key)
    print(f"Original filename: {encrypted['original_filename']}")
    print(f"Original size: {encrypted['original_size']} bytes")
    
    print("\nDECRYPTION")
    output_file = "files/test_output.txt"
    verified = manager.decrypt_file(encrypted, key, output_file)
    
    with open(output_file, 'rb') as f:
        decrypted_content = f.read()
    
    print("\n--- VERIFICATION ---")
    print(f"Integrity verified: {verified}")
    # print(f"Content matches: {test_content == decrypted_content}")