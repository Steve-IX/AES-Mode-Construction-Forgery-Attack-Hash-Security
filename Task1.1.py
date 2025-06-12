
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings, truncating to the length of the shorter input.
    """
    return bytes(x ^ y for x, y in zip(a, b))

'''
:param key:  str - The hex value of the key to be used for encryption
:param iv:   str - The hex value of the initialisation vector
:param data: str - The UTF-8 plaintext to be encrypted
:return:     str - The hex value of the encrypted data
'''
def Encrypt(key: str, iv: str, data: str) -> str:
    # 1) Convert key & IV from hex to bytes
    key_bytes = bytes.fromhex(key)
    iv_bytes  = bytes.fromhex(iv)
    # 2) Convert plaintext to bytes
    plaintext_bytes = data.encode("utf-8")

    # 3) Set up AES-ECB encryptor
    aes_ecb = Cipher(
        algorithms.AES(key_bytes),
        modes.ECB(),
        backend=default_backend()
    ).encryptor()

    # 4) Encrypt IV once to obtain a 16-byte keystream
    keystream = aes_ecb.update(iv_bytes) + aes_ecb.finalize()

    # 5) XOR each 16-byte block of plaintext with the keystream.
    #    If the block is shorter or longer data is used, we wrap/trim the keystream.
    block_size = 16
    ciphertext = b""

    for start in range(0, len(plaintext_bytes), block_size):
        block = plaintext_bytes[start:start + block_size]
        # If block < 16 bytes, just use the corresponding portion of keystream
        # If block == 16 bytes, it matches exactly
        # If we had more than 16 (which shouldn't happen in a single block),
        # we could wrap around. But typical chunking is 16 bytes at a time.
        keystream_slice = keystream[:len(block)]
        ciphertext_block = _xor_bytes(block, keystream_slice)
        ciphertext += ciphertext_block

    # 6) Return the resulting ciphertext in hex
    return ciphertext.hex()

'''
:param key:  str - The hex value of the key to be used for decryption
:param iv:   str - The hex value of the initialisation vector
:param data: str - The hex value of the ciphertext
:return:     str - The decrypted data in UTF-8
'''
def Decrypt(key: str, iv: str, data: str) -> str:
    # 1) Convert key & IV from hex to bytes
    key_bytes = bytes.fromhex(key)
    iv_bytes  = bytes.fromhex(iv)
    # 2) Convert ciphertext (hex) back to bytes
    ciphertext_bytes = bytes.fromhex(data)

    # 3) Recreate the same AES-ECB encryptor and encrypt the IV
    aes_ecb = Cipher(
        algorithms.AES(key_bytes),
        modes.ECB(),
        backend=default_backend()
    ).encryptor()

    keystream = aes_ecb.update(iv_bytes) + aes_ecb.finalize()

    # 4) XOR each 16-byte block of ciphertext with the same keystream
    block_size = 16
    plaintext = b""

    for start in range(0, len(ciphertext_bytes), block_size):
        block = ciphertext_bytes[start:start + block_size]
        keystream_slice = keystream[:len(block)]
        plaintext_block = _xor_bytes(block, keystream_slice)
        plaintext += plaintext_block

    # 5) Convert the plaintext bytes to UTF-8 string
    return plaintext.decode("utf-8")

# Example local test 
if __name__ == "__main__":
    key  = "2b7e151628aed2a6abf7158809cf4f3c"
    iv   = "000102030405060708090a0b0c0d0e0f"
    text = "Hello World"

    ct = Encrypt(key, iv, text)
    pt = Decrypt(key, iv, ct)
    print(ct)  # Expect 189b0ba0f64d65d9a86553
    print(pt)  # Expect "Hello World"
