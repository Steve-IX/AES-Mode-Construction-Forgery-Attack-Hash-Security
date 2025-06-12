# -- START OF YOUR CODERUNNER SUBMISSION CODE

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_encrypt_block(key_bytes: bytes, block16: bytes) -> bytes:
    """
    Encrypt exactly 16 bytes (or fewer) under AES-ECB, returning 16 bytes.
    If 'block16' is shorter than 16 bytes, we still produce a 16-byte result
    and only XOR the needed portion later.
    """
    cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.ECB()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(block16) + encryptor.finalize()

def xor_portion(a: bytes, b: bytes) -> bytes:
    """
    XOR the overlapping portion of 'a' and 'b', truncating to min(len(a), len(b)).
    Returns bytes of that truncated length.
    """
    return bytes(x ^ y for x, y in zip(a, b))

def Encrypt(key: str, iv: str, data: str) -> str:
    """
    Encrypt function (brand-new logic) for the custom AES chaining:
    - Convert all inputs to bytes.
    - Start a 'previous_value' as the IV.
    - For each 16-byte snippet of plaintext, encrypt 'previous_value' under AES-ECB,
      XOR it with that snippet, and update 'previous_value' to the new ciphertext snippet.
    - Return the accumulated ciphertext in hex.
    """
    key_bytes = bytes.fromhex(key)
    iv_bytes  = bytes.fromhex(iv)
    plain_bytes = data.encode("utf-8")

    cipher_agg = []
    previous_value = iv_bytes
    cursor = 0
    chunk_size = 16

    # Process 16-byte slices in a while loop
    while cursor < len(plain_bytes):
        snippet = plain_bytes[cursor : cursor + chunk_size]
        cursor += chunk_size

        # Encrypt the previous_value to get a 16-byte "mask"
        mask = aes_encrypt_block(key_bytes, previous_value)

        # XOR just enough bytes of 'mask' with 'snippet'
        # to produce the next ciphertext snippet
        cfrag = xor_portion(snippet, mask[: len(snippet)])

        # Accumulate this ciphertext fragment
        cipher_agg.append(cfrag)

        # Update 'previous_value' to the newly created ciphertext portion
        previous_value = cfrag

    # Join all ciphertext parts and output hex
    final_cipher = b"".join(cipher_agg)
    return final_cipher.hex()

def Decrypt(key: str, iv: str, data: str) -> str:
    """
    Decrypt function for the same AES chaining:
    - Convert everything to bytes.
    - 'previous_value' starts as IV.
    - For each 16-byte snippet of ciphertext, encrypt 'previous_value'
      under AES-ECB, XOR result with snippet => plaintext snippet.
    - 'previous_value' then becomes the snippet we just decrypted.
    - Return the final plaintext as a UTF-8 string.
    """
    key_bytes = bytes.fromhex(key)
    iv_bytes  = bytes.fromhex(iv)
    cipher_bytes = bytes.fromhex(data)

    plain_agg = []
    previous_value = iv_bytes
    cursor = 0
    chunk_size = 16

    while cursor < len(cipher_bytes):
        snippet = cipher_bytes[cursor : cursor + chunk_size]
        cursor += chunk_size

        # Re-encrypt 'previous_value'
        mask = aes_encrypt_block(key_bytes, previous_value)

        # XOR with current ciphertext snippet => plaintext chunk
        pfrag = xor_portion(snippet, mask[: len(snippet)])
        plain_agg.append(pfrag)

        # Update for next iteration
        previous_value = snippet

    final_plain = b"".join(plain_agg)
    return final_plain.decode("utf-8")

# -- END OF YOUR CODERUNNER SUBMISSION CODE


# --------------------------------------------------------------------
# Example local test (NOT in CodeRunner):
if __name__ == "__main__":
    sample_key = "2b7e151628aed2a6abf7158809cf4f3c"
    sample_iv  = "000102030405060708090a0b0c0d0e0f"
    sample_msg = "Hello World"

    encrypted_hex = Encrypt(sample_key, sample_iv, sample_msg)
    decrypted_txt = Decrypt(sample_key, sample_iv, encrypted_hex)

    print("Ciphertext:", encrypted_hex)  # e.g. "189b0ba0f64d65d9a86553" for short data
    print("Plaintext: ", decrypted_txt)  # "Hello World"
