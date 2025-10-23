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

    def load_key(self, file_id):
        print(f"Loading key from file: {file_id}")

        key_file = os.path.join(self.key_store_path, f"{file_id}.key")

        if not os.path.exists(key_file):
            raise FileNotFoundError(f"Key file not found: {file_id}")
        
        with open(key_file, 'r') as f:
            key_b64 = f.read()

        key = b64decode(key_b64)

        print("Key loaded")
        return key

    def key_exists(self, file_id):
        key_file = os.path.join(self.key_store_path, f"{file_id}.key")
        exists = os.path.exists(key_file)
        print(f"Key exists for {file_id} : {exists}")
        return exists
    
    def list_keys(self):
        with open(self.key_index_file, 'r') as f:
            keys = json.load(f)

        print(f"Found {keys} keys")
        return keys
    
    def delete_key(self, file_id):
        print(f"Deleting key for file: {file_id}")
        
        key_file = os.path.join(self.key_store_path, f"{file_id}.key")
        
        if os.path.exists(key_file):
            os.remove(key_file)
        
        with open(self.key_index_file, 'r') as f:
            index = json.load(f)
        
        if file_id in index:
            del index[file_id]
        
        with open(self.key_index_file, 'w') as f:
            json.dump(index, f, indent=4)
        
        print("Key deleted")

if __name__ == "__main__":
    print("Testing KeyManager")
    
    import tempfile
    import shutil
    
    temp_dir = tempfile.mkdtemp()
    print(f"\nCreated temporary key store: {temp_dir}")
    
    try:
        manager = KeyManager(key_store_path=temp_dir)
        
        test_key = os.urandom(32)  # 256-bit key
        file_id = "test-file-123"
        
        print("\n--- SAVING KEY ---")
        manager.save_key(file_id, test_key)
        
        print("\n--- CHECKING KEY EXISTS ---")
        exists = manager.key_exists(file_id)
        print(f"Key exists: {exists}")
        
        print("\n--- LOADING KEY ---")
        loaded_key = manager.load_key(file_id)
        print(f"Keys match: {test_key == loaded_key}")
        
        print("\n--- LISTING KEYS ---")
        keys = manager.list_keys()
        for fid, info in keys.items():
            print(f"{fid}: {info}")
        
        print("\n--- DELETING KEY ---")
        manager.delete_key(file_id)
        exists_after = manager.key_exists(file_id)
        print(f"Key exists after deletion: {exists_after}")
        
        print("\nAll tests passed!")
        
    finally:
        shutil.rmtree(temp_dir)
        print(f"\nCleaned up temporary directory")