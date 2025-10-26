# ============================================================
#  Custom Block Cipher: Toy Block Cipher
# ============================================================

from typing import List 
import hashlib 
import struct 

BLOCK_SIZE = 8  # bytes (64-bit block) 

# Padding function 

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes: 

    pad_len = block_size - (len(data) % block_size) 

    if pad_len == 0: 

        pad_len = block_size 

    return data + bytes([pad_len]) * pad_len 

 

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes: 

    if not data or len(data) % block_size != 0: 

        raise ValueError("Invalid padded data length") 

    pad_len = data[-1] 

    if pad_len < 1 or pad_len > block_size: 

        raise ValueError("Invalid padding") 

    if data[-pad_len:] != bytes([pad_len]) * pad_len: 

        raise ValueError("Invalid padding bytes") 

    return data[:-pad_len] 

 

def _rotl32(x: int, r: int) -> int: 

    return ((x << r) & 0xFFFFFFFF) | (x >> (32 - r)) 

 

# Key Schedule/ Expansion 

def derive_round_keys(key: bytes, rounds: int) -> List[int]: 

    if len(key) == 0: 

        raise ValueError("Key must be non-empty") 

    round_keys = [] 

    counter = 0 

    while len(round_keys) < rounds: 

        h = hashlib.sha256(key + counter.to_bytes(4, 'big')).digest() 

        for i in range(0, len(h), 4): 

            if len(round_keys) < rounds: 

                round_keys.append(int.from_bytes(h[i:i+4], 'big')) 

        counter += 1 

    return round_keys[:rounds] 

 

# Round Function 

def round_function(r: int, round_key: int) -> int: 

    x = (r + (round_key & 0xFFFFFFFF)) & 0xFFFFFFFF 

    x = _rotl32(x ^ 0xA5A5A5A5, (round_key ^ x) & 31) 

    x = (x * 0x9E3779B1) & 0xFFFFFFFF 

    x ^= ((round_key >> 16) | (round_key << 16)) & 0xFFFFFFFF 

    return x & 0xFFFFFFFF 

 

def encrypt_block(block: bytes, round_keys: List[int]) -> bytes: 

    if len(block) != BLOCK_SIZE: 

        raise ValueError("Block must be exactly 8 bytes") 

    L, R = struct.unpack(">II", block) 

    for k in round_keys: 

        new_L = R 

        new_R = L ^ round_function(R, k) 

        L, R = new_L, new_R 

    return struct.pack(">II", L, R) 

 

def decrypt_block(block: bytes, round_keys: List[int]) -> bytes: 

    if len(block) != BLOCK_SIZE: 

        raise ValueError("Block must be exactly 8 bytes") 

    L, R = struct.unpack(">II", block) 

    for k in reversed(round_keys): 

        new_R = L 

        new_L = R ^ round_function(L, k) 

        L, R = new_L, new_R 

    return struct.pack(">II", L, R) 

 

def encrypt(plaintext: bytes, key: bytes, rounds: int = 8) -> bytes: 

    if rounds < 1: 

        raise ValueError("rounds must be at least 1") 

    round_keys = derive_round_keys(key, rounds) 

    padded = pkcs7_pad(plaintext, BLOCK_SIZE) 

    ciphertext = bytearray() 

    for i in range(0, len(padded), BLOCK_SIZE): 

        blk = padded[i:i+BLOCK_SIZE] 

        ciphertext.extend(encrypt_block(blk, round_keys)) 

    return bytes(ciphertext) 

 

 

def decrypt(ciphertext: bytes, key: bytes, rounds: int = 8) -> bytes: 

    if rounds < 1: 

        raise ValueError("rounds must be at least 1") 

    if len(ciphertext) % BLOCK_SIZE != 0: 

        raise ValueError("Invalid ciphertext length") 

    round_keys = derive_round_keys(key, rounds) 

    plaintext_padded = bytearray() 

    for i in range(0, len(ciphertext), BLOCK_SIZE): 

        blk = ciphertext[i:i+BLOCK_SIZE] 

        plaintext_padded.extend(decrypt_block(blk, round_keys)) 

    return pkcs7_unpad(bytes(plaintext_padded), BLOCK_SIZE) 

# ============================================================
#                       DEMO SECTION
# ============================================================

def _demo(): 

    key = b"supersecretkey!" 

    rounds = 8 

    plaintext = b"Attack at dawn!" 

    print("Plaintext:", plaintext) 

    ct = encrypt(plaintext, key, rounds=rounds) 

    print("Ciphertext (hex):", ct.hex()) 

    pt = decrypt(ct, key, rounds=rounds) 

    print("Recovered plaintext:", pt) 

    assert pt == plaintext, "Decryption failed: plaintext mismatch" 

    print("Round-trip successful.") 

 

if __name__ == "__main__": 

    _demo()