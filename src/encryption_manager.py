import json
import os
import hashlib
from base64 import b64encode, b64decode
import struct

class AES:
    
    sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    
    inv_sbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]
    
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    
    def __init__(self, key):
        self.key_size = len(key)
        if self.key_size == 16:
            self.rounds = 10
        elif self.key_size == 24:
            self.rounds = 12
        elif self.key_size == 32:
            self.rounds = 14
        else:
            raise ValueError("Key must be 16, 24, or 32 bytes")
        
        self.round_keys = self._key_expansion(key)
    
    def _key_expansion(self, key):
        key_words = len(key) // 4
        total_words = 4 * (self.rounds + 1)
        round_keys = [[0] * 4 for _ in range(total_words)]
        
        for i in range(key_words):
            round_keys[i] = list(key[i*4:i*4+4])
        
        for i in range(key_words, total_words):
            temp = round_keys[i - 1][:]
            
            if i % key_words == 0:
                temp = temp[1:] + temp[:1]
                temp = [self.sbox[b] for b in temp]
                temp[0] ^= self.rcon[(i // key_words) - 1]
            elif key_words > 6 and i % key_words == 4:
                temp = [self.sbox[b] for b in temp]
            
            new_word = [temp[j] ^ round_keys[i - key_words][j] for j in range(4)]
            round_keys[i] = new_word
        
        return round_keys
    
    def _add_round_key(self, state, round_key):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[j][i]
    
    def _sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = self.sbox[state[i][j]]
    
    def _inv_sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = self.inv_sbox[state[i][j]]
    
    def _shift_rows(self, state):
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
    
    def _inv_shift_rows(self, state):
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
    
    def _xtime(self, a):
        return ((a << 1) ^ (0x1b if a & 0x80 else 0)) & 0xff
    
    def _mix_single_column(self, col):
        c0, c1, c2, c3 = col
        t = self._xtime
        return [
            t(c0) ^ t(c1) ^ c1 ^ c2 ^ c3,
            c0 ^ t(c1) ^ t(c2) ^ c2 ^ c3,
            c0 ^ c1 ^ t(c2) ^ t(c3) ^ c3,
            t(c0) ^ c0 ^ c1 ^ c2 ^ t(c3)
        ]
    
    def _mix_columns(self, state):
        for j in range(4):
            col = [state[i][j] for i in range(4)]
            mixed_col = self._mix_single_column(col)
            for i in range(4):
                state[i][j] = mixed_col[i]
    
    def _inv_mix_single_column(self, col):
        c0, c1, c2, c3 = col
        u = self._xtime(self._xtime(c0 ^ c2))
        v = self._xtime(self._xtime(c1 ^ c3))
        c0 ^= u
        c1 ^= v
        c2 ^= u
        c3 ^= v
        return self._mix_single_column([c0, c1, c2, c3])
    
    def _inv_mix_columns(self, state):
        for j in range(4):
            col = [state[i][j] for i in range(4)]
            inv_mixed_col = self._inv_mix_single_column(col)
            for i in range(4):
                state[i][j] = inv_mixed_col[i]
    
    def _bytes_to_state(self, block):
        state = [[0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[i][j] = block[i + 4 * j]
        return state
    
    def _state_to_bytes(self, state):
        block = []
        for j in range(4):
            for i in range(4):
                block.append(state[i][j])
        return bytes(block)
    
    def encrypt_block(self, plaintext):
        state = self._bytes_to_state(plaintext)
        
        self._add_round_key(state, self.round_keys[0:4])
        
        for round_num in range(1, self.rounds):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self.round_keys[round_num * 4:(round_num + 1) * 4])
        
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.round_keys[self.rounds * 4:(self.rounds + 1) * 4])
        
        return self._state_to_bytes(state)
    
    def decrypt_block(self, ciphertext):
        state = self._bytes_to_state(ciphertext)
        
        self._add_round_key(state, self.round_keys[self.rounds * 4:(self.rounds + 1) * 4])
        
        for round_num in range(self.rounds - 1, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, self.round_keys[round_num * 4:(round_num + 1) * 4])
            self._inv_mix_columns(state)
        
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, self.round_keys[0:4])
        
        return self._state_to_bytes(state)


class Padding:
    
    def __init__(self, block_size=16):
        self.block_size = block_size
    
    def pad(self, data):
        padding_length = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def unpad(self, data):
        padding_length = data[-1]
        if padding_length > 16 or padding_length == 0:
             raise ValueError("Invalid padding")
        if data[-padding_length:] != bytes([padding_length] * padding_length):
             raise ValueError("Invalid padding")
        return data[:-padding_length]


class EncryptionManager:
    def __init__(self, key_size=256):
        self.key_size = key_size
        self.block_size = 128
        self.padding = Padding(block_size=16)
        print("initialized")

    def generate_key(self):
        key_bytes = self.key_size // 8
        key = os.urandom(key_bytes)
        print(f"generated encryption key: {self.key_size} bit")
        return key
    
    def generate_iv(self):
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

        padded_data = self.padding.pad(plaintext)
        print(f"padded data to {len(padded_data)} bytes")

        cipher = AES(key)
        
        ciphertext = bytearray()
        previous_block = iv
        
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            xored_block = bytes([block[j] ^ previous_block[j] for j in range(16)])
            encrypted_block = cipher.encrypt_block(xored_block)
            ciphertext.extend(encrypted_block)
            previous_block = encrypted_block

        print(f"encryption done")

        return {
            'ciphertext': b64encode(bytes(ciphertext)).decode('utf-8'),
            'iv': b64encode(iv).decode('utf-8'),
            'original_hash': original_hash,
            'key_size': self.key_size
        }

    def decrypt_data(self, encrypted_data, key):
        ciphertext = b64decode(encrypted_data['ciphertext'])
        iv = b64decode(encrypted_data['iv'])
        original_hash = encrypted_data.get('original_hash', None)

        cipher = AES(key)
        
        plaintext_padded = bytearray()
        previous_block = iv
        
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = cipher.decrypt_block(block)
            xored_block = bytes([decrypted_block[j] ^ previous_block[j] for j in range(16)])
            plaintext_padded.extend(xored_block)
            previous_block = block
        
        try:
            plaintext = self.padding.unpad(bytes(plaintext_padded))
        except ValueError as e:
            print(f"Decryption failed: {e}. Possible wrong key or corrupted data.")
            return None, False

        calculated_hash = self.calculate_hash(plaintext)
        
        if original_hash:
            integrity_verified = (calculated_hash == original_hash)
            if integrity_verified:
                print(f"Integrity verified")
            else:
                print(f"Integrity check Failed: Hashes do not match!")
        else:
            print("No original hash provided, skipping integrity check.")
            integrity_verified = False 

        print("Decryption completed")

        return plaintext, integrity_verified
    
    def encrypt_file(self, file_path, key):
        print(f"Encrypting file : {file_path}")

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
        except FileNotFoundError:
            print(f"Error: File not found at {file_path}")
            return None
        
        print(f"File size : {len(file_data)} bytes")

        encrypted_data = self.encrypt_data(file_data, key)
        encrypted_data['original_filename'] = os.path.basename(file_path)
        encrypted_data['original_size'] = len(file_data)

        print("File encryption completed")

        return encrypted_data

    def decrypt_file(self, encrypted_data, key, output_path):
        print(f"\nDecrypting file to: {output_path}")

        plaintext, integrity_verified = self.decrypt_data(encrypted_data, key)

        if plaintext is not None:
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            print(f"File written: {len(plaintext)} bytes")
        else:
            print("Decryption returned no data. Output file not written.")

        return integrity_verified


if __name__ == "__main__":
    test_content = b"This is a test file with sensitive data!\nLine 2\nLine 3"
    test_file = "test_file.txt"
    output_file = "test_output.txt"
    
    with open(test_file, 'wb') as f:
        f.write(test_content)

    manager = EncryptionManager(key_size=256)
    key = manager.generate_key()


    print("\nENCRYPTION")
    encrypted = manager.encrypt_file(test_file, key)
    
    if encrypted:
        print(f"Original filename: {encrypted['original_filename']}")
        print(f"Original size: {encrypted['original_size']} bytes")
        
        print("\nDECRYPTION")
        verified = manager.decrypt_file(encrypted, key, output_file)
        
        try:
            with open(output_file, 'rb') as f:
                decrypted_content = f.read()
            
            print("\n--- VERIFICATION ---")
            print(f"Integrity verified: {verified}")
            print(f"Content matches: {test_content == decrypted_content}")

            os.remove(test_file)
            os.remove(output_file)
            print(f"Cleaned up {test_file} and {output_file}")

        except FileNotFoundError:
            print("Decryption failed, output file was not created.")
        except Exception as e:
            print(f"An error occurred during verification: {e}")