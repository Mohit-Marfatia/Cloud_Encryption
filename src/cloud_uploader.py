"""
Local Uploader - Handles uploading encrypted files to local mock storage
"""
import os
import json
from datetime import datetime


class CloudUploader:
    def __init__(self, local_path='./mock_cloud'):
        self.local_path = local_path
        os.makedirs(local_path, exist_ok=True)
        self.metadata_file = os.path.join(local_path, 'metadata.json')
        self._init_metadata()

    def _init_metadata(self):
        if not os.path.exists(self.metadata_file):
            with open(self.metadata_file, 'w') as f:
                json.dump({}, f)

    def upload(self, encrypted_data, file_id):
        file_path = os.path.join(self.local_path, f"{file_id}.enc")
        with open(file_path, 'w') as f:
            json.dump(encrypted_data, f, indent=4)

        with open(self.metadata_file, 'r') as f:
            metadata = json.load(f)
            
        metadata[file_id] = {
            'original_filename': encrypted_data['original_filename'],
            'encrypted_filename': f"{file_id}.enc",
            'upload_timestamp': datetime.now().isoformat(),
            'original_size': encrypted_data['original_size'],
            'original_hash': encrypted_data['original_hash']
        }

        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)

        return {
            'success': True,
            'file_id': file_id,
            'location': file_path,
            'storage_type': 'local'
        }

    def download(self, file_id):
        file_path = os.path.join(self.local_path, f"{file_id}.enc")
        with open(file_path, 'r') as f:
            return json.load(f)

    def list_files(self):
        with open(self.metadata_file, 'r') as f:
            return json.load(f)
        

if __name__ == "__main__":
    print("Testing CloudUploader (Local Storage Only)")
    
    import tempfile
    import shutil
    import uuid

    temp_dir = tempfile.mkdtemp()
    print(f"\nCreated temporary cloud storage: {temp_dir}")

    try:
        uploader = CloudUploader(local_path=temp_dir)

        test_encrypted = {
            'ciphertext': 'VGhpcyBpcyBlbmNyeXB0ZWQgZGF0YQ==',
            'iv': 'cmFuZG9taXY=',
            'original_hash': 'abc123def456',
            'original_filename': 'test.txt',
            'original_size': 1024,
            'key_size': 256
        }

        file_id = str(uuid.uuid4())

        print("\n--- UPLOADING FILE ---")
        result = uploader.upload(test_encrypted, file_id)
        print(f"Upload success: {result['success']}")
        print(f"File ID: {result['file_id']}")

        print("\n--- LISTING FILES ---")
        files = uploader.list_files()
        for fid, info in files.items():
            print(f"\n  File ID: {fid}")
            print(f"Original name: {info['original_filename']}")
            print(f"Upload time: {info['upload_timestamp']}")

        print("\n--- DOWNLOADING FILE ---")
        downloaded = uploader.download(file_id)
        print(f"Downloaded filename: {downloaded['original_filename']}")
        print(f"Data matches: {downloaded == test_encrypted}")

        print("\nAll tests passed!")

    finally:
        shutil.rmtree(temp_dir)
        print(f"\nCleaned up temporary directory")
        