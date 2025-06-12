# -- START OF YOUR CODERUNNER SUBMISSION CODE
# INCLUDE MODULES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import binascii

# INCLUDE HELPER FUNCTIONS YOU IMPLEMENT
def pad(data: bytes) -> bytes:
    """
    Pad the input data to be compatible with AES block size (128 bits).
    :param data: bytes: The plaintext data to be padded.
    :return: bytes: The padded data.
    """
    padder = PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad(data: bytes) -> bytes:
    """
    Unpad the input data to remove the padding applied during encryption.
    :param data: bytes: The padded data to be unpadded.
    :return: bytes: The unpadded data.
    """
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

'''
:param key: str: The hexadecimal value of a key to be used for encryption
:param iv: str: The hexadecimal value of an initialisation vector to be
used for encryption
:param data: str: The data to be encrypted
:return: str: The hexadecimal value of encrypted data
'''
def Encrypt(key: str, iv: str, data: str) -> str:
    # Convert key, IV, and data to bytes
    key_bytes = binascii.unhexlify(key)
    iv_bytes = binascii.unhexlify(iv)
    data_bytes = data.encode('utf-8')

    # Pad the data to match AES block size
    padded_data = pad(data_bytes)

    # Initialize AES cipher in ECB mode
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the data
    encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()

    # Convert encrypted bytes to hexadecimal
    return binascii.hexlify(encrypted_bytes).decode('utf-8')

'''
:param key: str: The hexadecimal value of a key to be used for decryption
:param iv: str: The hexadecimal value of the initialisation vector to be
used for decryption
:param data: str: The hexadecimal value of the data to be decrypted
:return: str: The decrypted data in UTF-8 format
'''
def Decrypt(key: str, iv: str, data: str) -> str:
    # Convert key, IV, and encrypted data to bytes
    key_bytes = binascii.unhexlify(key)
    iv_bytes = binascii.unhexlify(iv)
    encrypted_bytes = binascii.unhexlify(data)

    # Initialize AES cipher in ECB mode
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_padded_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()

    # Unpad the decrypted data
    decrypted_bytes = unpad(decrypted_padded_bytes)

    # Convert bytes to UTF-8 string
    return decrypted_bytes.decode('utf-8')

# -- END OF YOUR CODERUNNER SUBMISSION CODE

# Main
if __name__ == "__main__":
    # Task 1
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    iv = "000102030405060708090a0b0c0d0e0f"
    text = "Hello World"

    ct = Encrypt(key, iv, text)
    pt = Decrypt(key, iv, ct)
    print("Ciphertext (Encrypted):", ct)
    print("Plaintext (Decrypted):", pt)
