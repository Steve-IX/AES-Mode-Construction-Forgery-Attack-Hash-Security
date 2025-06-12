
import hashlib
import os

"""
:param data: bytes - The data to be hashed
:return: bytes - The final 4-byte (32-bit) hash
"""
def myHash(data: bytes) -> bytes:
    """
    This function implements the hashing steps shown in Figure 3:
    1) Compute SHA-256 on the input data (32 bytes, 256 bits).
    2) Split the 32-byte SHA-256 hash into two 16-byte halves, XOR -> Value A (16 bytes).
    3) Split Value A into two 8-byte halves, XOR -> Value B (8 bytes).
    4) Split Value B into two 4-byte halves, XOR -> final 4-byte output hash.
    """
    # Step 1: Compute SHA-256
    full_hash = hashlib.sha256(data).digest()  # 32 bytes

    # Step 2: Split and XOR to get 16-byte Value A
    first_16 = full_hash[:16]
    second_16 = full_hash[16:]
    valueA = bytes(a ^ b for a, b in zip(first_16, second_16))

    # Step 3: Split Value A (16 bytes) and XOR -> 8-byte Value B
    a1 = valueA[:8]
    a2 = valueA[8:]
    valueB = bytes(a ^ b for a, b in zip(a1, a2))

    # Step 4: Split Value B (8 bytes) and XOR -> final 4-byte output
    b1 = valueB[:4]
    b2 = valueB[4:]
    output_hash = bytes(a ^ b for a, b in zip(b1, b2))

    return output_hash


"""
:return: str - Return "YES" if myHash is secure and "NO" otherwise
"""
def myAttack() -> str:
    """
    This function demonstrates a collision-finding attack (birthday attack)
    to test the security of myHash. Because myHash outputs only 32 bits,
    collisions can be found relatively quickly.

    Attack Strategy:
    1) Repeatedly generate random data, compute myHash(data).
    2) Store hash -> data mappings in a dictionary.
    3) If we ever see the same 4-byte hash from different inputs, we have a collision.
    4) If we find a collision within a reasonable number of tries, return "NO".
       Otherwise, return "YES".

    Note: In practice, 2^32 is about 4.3 billion. The average collision
    is found around 2^(32/2) = 65,536 tries via the Birthday Paradox.
    We'll attempt a fraction of that for demonstration.
    """
    seen = {}
    max_attempts = 100000  # artificial cutoff for demonstration

    for _ in range(max_attempts):
        random_data = os.urandom(8)  # 8 random bytes
        h = myHash(random_data)
        if h in seen:
            # Check that we didn't get the exact same data
            if seen[h] != random_data:
                # We found a collision -> myHash is not secure
                return "NO"
        else:
            seen[h] = random_data

    # If we haven't found any collision in 'max_attempts', we claim "YES"
    # though in reality, the hash is still only 32 bits, so a collision is likely if we try long enough.
    return "YES"


# -------------------------------------------------------------------------
# Test locally (NOT in CodeRunner):
if __name__ == "__main__":
    # Example test for myHash with the string "a"
    print("myHash(b'a') =", myHash(b"a"))
    # Example test for myAttack
    print("myAttack() =", myAttack())
