import os
import json
from base64 import b64encode, b64decode
from datetime import datetime

class KeyManager:
    def __init__(self, key_store_path='./keys'):
        self.key_store_path = key_store_path
        os.makedirs(key_store_path, exist_ok=True)
        self.key_index_file = os.path.join(key_store_path, 'key_index.json')
        self._init_key_index()
        print(f"Initialised with key store: {key_store_path}")

    def _init_key_index(self):
        if not os.path.exists(self.key_index_file):
            with open(self.key_index_file, 'w') as f:
                json.dump({}, f)
            print(f"Created new key index")

    def save_key(self, file_id, key):
        print(f"saving key for file: {file_id}")

        key_file = os.path.join(self.key_store_path, f"{file_id}.key")
        with open(key_file, 'w') as f:
            f.write(b64encode(key).decode('utf-8'))

        with open(self.key_index_file, 'r') as f:
            index = json.load(f)
        
        index[file_id] = {
            'key_file': f"{file_id}.key",
            'created': datetime.now().isoformat(),
            'key_size': len(key) * 8 #bits
        }

        with open(self.key_index_file, 'w') as f:
            json.dump(index, f, indent=4)

        print("Key saved")
