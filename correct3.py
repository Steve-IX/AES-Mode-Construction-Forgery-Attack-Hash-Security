# -- START OF YOUR CODERUNNER SUBMISSION CODE
def attackAESMode(plaintext1: str, ciphertext1: bytes, plaintext2: str) -> bytes:
    """
    :param plaintext1: str    - The known plaintext for which ciphertext1 is given
    :param ciphertext1: bytes - The ciphertext that corresponds to plaintext1
    :param plaintext2: str    - The new plaintext to be 'encrypted' under the same flawed mode
    :return: bytes            - The resulting ciphertext for plaintext2
    """
    # 1) Convert all strings to bytes.
    p1_bytes = plaintext1.encode('utf-8')
    p2_bytes = plaintext2.encode('utf-8')

    # 2) Recover the keystream from plaintext1 and ciphertext1.
    #    Because the scheme in Figure 2 uses the same AES(IV1) for *every* 16-byte block,
    #    we only need to recover 16 bytes of keystream (or as many as plaintext1 provides).
    #    keystream_block[i] = ciphertext1[i] XOR plaintext1[i] for i in [0..15].
    block_size = 16

    # Take whichever is smaller: either 16, or the full length of the known plaintext/ciphertext.
    # (If plaintext1 was shorter than 16 bytes, we only recover that many keystream bytes.)
    keystream_len = min(len(p1_bytes), len(ciphertext1), block_size)

    # Recover the portion we can
    keystream_block = bytes(
        c1 ^ p1 for c1, p1 in zip(ciphertext1[:keystream_len], p1_bytes[:keystream_len])
    )

    # 3) "Encrypt" plaintext2 by XORing each 16-byte block with the same keystream_block.
    #    If plaintext2 is longer than keystream_block, we keep reusing it (since the figure
    #    shows the same AES(IV1) for every block).
    ciphertext2 = bytearray()

    for i in range(0, len(p2_bytes), keystream_len):
        block = p2_bytes[i : i + keystream_len]
        # XOR with the keystream_block (repeat it if needed)
        # but typically keystream_len is 16, so that covers each block
        ct_block = bytes(b ^ k for b, k in zip(block, keystream_block))
        ciphertext2.extend(ct_block)

    # 4) Return the newly crafted ciphertext as bytes.
    return bytes(ciphertext2)
# -- END OF YOUR CODERUNNER SUBMISSION CODE
