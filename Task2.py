

def attackAESMode(plaintext1: str, ciphertext1: bytes, plaintext2: str) -> bytes:
    """
    :param plaintext1: str    - The known plaintext for which ciphertext1 is given
    :param ciphertext1: bytes - The ciphertext that corresponds to plaintext1
    :param plaintext2: str    - The new plaintext that we want to encrypt under the same flawed mode
    :return: bytes            - The resulting ciphertext for plaintext2
    """

    # 1) Convert plaintext strings to bytes (UTF-8 encoding assumed).
    p1_bytes = plaintext1.encode('utf-8')
    p2_bytes = plaintext2.encode('utf-8')

    # 2) Recover the repeated AES(IV1) keystream by XORing plaintext1 and ciphertext1.
    #    For each byte i: keystream[i] = ciphertext1[i] XOR p1_bytes[i].
    #    Note: We zip them so that if there's any minor length mismatch, we only process the minimum.
    keystream = bytes(c1 ^ p1 for c1, p1 in zip(ciphertext1, p1_bytes))

    # 3) Encrypt plaintext2 by XORing it with the recovered keystream.
    #    ciphertext2[i] = keystream[i] XOR p2_bytes[i].
    ciphertext2 = bytes(k ^ p2 for k, p2 in zip(keystream, p2_bytes))

    # 4) Return the newly crafted ciphertext for plaintext2.
    return ciphertext2


# -----------------------------------------------------------------------------
# You can test your code in your system 
if __name__ == "__main__":
    pt1 = (
        "This is your General. Hold position until further orders. "
        "I repeat, hold position."
    )
    ct1 = (
        b'\xf2\x0f\x97#$D\xa8\xda\xa0\xe4:TQ\x82%\xc3\x15\x9f<*\r\x93\x95\xb5\xef5'
        b'8\x1be\x8e?\xcf\x08\x90pqC\xaf\x93\xb5\xabs=\x06b\x8f.\xd4G\x91"H\xa9\x89'
        b'\xf7\xab\\h\x06s\x97.\xc7\x13\xd2plB\xb7\x9e\xf9\xfbz;\x1db\x8e$\xc8I'
    )
    pt2 = (
        "This is your General. Proceed with the attack at dawn. "
        "I repeat, proceed with the attack at dawn."
    )

    new_ct = attackAESMode(pt1, ct1, pt2)
    print("Ciphertext for plaintext2 (in bytes):", new_ct)
