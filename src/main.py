"""
Main Application - Cloud Data Encryption Layer (Local Only)

Demonstrates client-side encryption before local cloud upload
"""

import os
import uuid
import argparse
from encryption_manager import EncryptionManager
from cloud_uploader import CloudUploader
from file_handler import KeyManager
from datetime import datetime


class CloudEncryptionApp:
    def __init__(self):
        self.encryption_manager = EncryptionManager(key_size=256)
        self.cloud_uploader = CloudUploader()
        self.key_manager = KeyManager()

        print(f"Cloud Data Encryption Layer initialized")
        print(f"Storage type: LOCAL")
        print(f"Encryption: AES-256-CBC")
        print(f"Integrity: SHA-256 hashing\n")

    def  encrypt_and_upload(self, file_path):
        print(f"Processing file: {file_path}")

        file_id = str(uuid.uuid4())

        print("Generating encryption key...")
        key = self.encryption_manager.generate_key()

        print("Encrypting file...")
        encrypted_data = self.encryption_manager.encrypt_file(file_path, key)

        print("Saving encryption key...")
        self.key_manager.save_key(file_id, key)

        print("Storing encrypted file locally...")
        result = self.cloud_uploader.upload(encrypted_data, file_id)

        if result['success']:
            print(f"Upload successful!")
            print(f"File ID: {file_id}")
            print(f"Original hash: {encrypted_data['original_hash'][:16]}...")
            print(f"Original size: {encrypted_data['original_size']} bytes")
        else:
            print(f"Upload failed: {result.get('error', 'Unknown error')}")

        return {**result, 'file_id': file_id}

    def download_and_decrypt(self, file_id, output_path):
        print(f"Downloading file: {file_id}")

        if not self.key_manager.key_exists(file_id):
            print(f"Encryption key not found for file ID: {file_id}")
            return False

        print("Loading encryption key...")
        key = self.key_manager.load_key(file_id)

        print("Fetching encrypted file locally...")
        encrypted_data = self.cloud_uploader.download(file_id)

        print("Decrypting file...")
        integrity_verified = self.encryption_manager.decrypt_file(
            encrypted_data, key, output_path
        )

        if integrity_verified:
            print(f"Decryption successful! Integrity verified.")
            print(f"Saved to: {output_path}")
        else:
            print(f"Decryption completed but integrity check FAILED!")
            print(f"File may be corrupted or tampered with.")

        return integrity_verified

    def list_files(self):
        print("\nUploaded Files:")
        files = self.cloud_uploader.list_files()

        if not files:
            print("No files uploaded yet.")
        else:
            for file_id, metadata in files.items():
                print(f"File ID: {file_id}")
                print(f"Original name: {metadata['original_filename']}")
                print(f"Upload time: {metadata['upload_timestamp']}")
                print(f"Size: {metadata['original_size']} bytes")


def demo():
    print("CLOUD DATA ENCRYPTION")
    print()

    app = CloudEncryptionApp()

    demo_dir = '../demo_files'
    os.makedirs(demo_dir, exist_ok=True)

    demo_file = os.path.join(demo_dir, 'sensitive_data.txt')
    with open(demo_file, 'w') as f:
        f.write("This is sensitive data that needs to be encrypted!\n")
        f.write("Account Number: 1234-5678-9012-3456\n")
        f.write("Password: SuperSecret123\n")

    print(f"Created demo file: {demo_file}\n")

    result = app.encrypt_and_upload(demo_file)
    file_id = result['file_id']

    print("Waiting before download...\n")

    output_file = os.path.join(demo_dir, 'decrypted_data.txt')
    app.download_and_decrypt(file_id, output_file)

    app.list_files()

    print("Verifying decrypted content:")
    with open(output_file, 'r') as f:
        content = f.read()
    print(f"\n{content}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Cloud Data Encryption Layer (Local)')
    parser.add_argument('--demo', action='store_true', help='Run demonstration')
    parser.add_argument('--encrypt', type=str, help='File to encrypt and upload')
    parser.add_argument('--decrypt', type=str, help='File ID to download and decrypt')
    parser.add_argument('--output', type=str, help='Output path for decrypted file')
    parser.add_argument('--list', action='store_true', help='List uploaded files')

    args = parser.parse_args()

    if args.demo:
        demo()
    elif args.list:
        app = CloudEncryptionApp()
        app.list_files()
    elif args.encrypt:
        app = CloudEncryptionApp()
        app.encrypt_and_upload(args.encrypt)
    elif args.decrypt and args.output:
        app = CloudEncryptionApp()
        app.download_and_decrypt(args.decrypt, args.output)
    else:
        parser.print_help()
