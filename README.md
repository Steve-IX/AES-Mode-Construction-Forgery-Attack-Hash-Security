# PyCrypto-Exercises – AES Mode Construction, Forgery Attack & Hash-Security Tester

**PyCrypto-Exercises** is a compact Python 3 codebase that walks through three fundamental cryptography skills:

| Task                         | Goal                                                                                                                                                     | Core techniques                                                                            |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| **01 AES-Mode Builder**      | Implement *Encrypt* and *Decrypt* for a bespoke block-cipher mode that internally calls AES-ECB.                                                         | PKCS7 padding · IV handling · byte/hex transforms                                          |
| **02 Ciphertext Forgery**    | Analyse the same mode, explain how it can be subverted, and craft a forged ciphertext that flips a “Hold position” order into “Proceed with the attack”. | Chosen-plaintext oracle · block swapping / bit-flipping · Python `cryptography` primitives |
| **03 Custom Hash + Breaker** | Design `myHash` (SHA-256 then length-truncation) and write `myAttack` that decides whether the construction is collision-resistant.                      | Merkle–Damgård length-extension awareness · collision search · statistical testing         |

The project is **100 % pure Python** with only widely available packages (`cryptography`, `numpy` for optional helpers).
All logic lives in fewer than 300 LoC and is heavily commented so you can trace each mathematical step.&#x20;

---

## Why this repository?

* **End-to-end learning path** – start from low-level AES building blocks, progress to real-world protocol mistakes, finish with hash-function evaluation.
* **Readable over clever** – clarity outweighs micro-optimisations; every transform is named, typed, and explained.
* **Hack-ready sandbox** – every module exposes a single public function so you can import and tweak experiments from a Jupyter notebook or another script.

---

## Repository layout

```
pycrypto-exercises/
├─ aes_mode.py            # Task 1  – Encrypt / Decrypt
├─ aes_attack.py          # Task 2  – attackAESMode()
├─ custom_hash.py         # Task 3  – myHash() + myAttack()
├─ demo.py                # CLI tester for all tasks
├─ requirements.txt       # cryptography>=42.0, numpy (optional)
└─ README.md              # you are here
```

*`demo.py` reproduces the sample runs shown below.*

---

## Quick start

```bash
# 1 – clone & install sandbox
git clone https://github.com/<you>/pycrypto-exercises.git
cd pycrypto-exercises
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2 – run demonstrations
python demo.py
```

Expected console output (abridged):

```
Task 1
  Ciphertext : 189b0ba0f64d65d9a86553
  Plaintext  : Hello World

Task 2
  Forged CT  : f20f97232444a8daa0e460...
  Decrypts to: This is your General. Proceed with the attack at dawn. ...

Task 3
  myHash('a')      -> c5f94f92
  myAttack verdict -> NO  (construction is not secure)
```

---

## Implementation highlights

### AES-Mode Builder (`aes_mode.py`)

* **Stateless core** – a tiny helper converts hex ⇆ bytes, another applies PKCS7; the AES context itself never leaks key material.
* **Streaming friendly** – although implemented in one shot for simplicity, the mode can be rewritten as a generator yielding blocks on the fly.

### Ciphertext Forgery (`aes_attack.py`)

* **Attack rationale embedded as docstring** – step-by-step commentary shows how the mode falls to either ECB cut-and-paste or CTR bit-flips (depending on your build).
* **Library compliance** – reuses `aes_mode.Encrypt` to stay honest; no magic “decrypt oracle” shortcuts.

### Hash & Breaker (`custom_hash.py`)

* **Truncated SHA-256** – `myHash` returns the first 32 bits, illustrating why naïve truncation lowers collision security from 2²⁵⁶ to 2³².
* **Generic attack** – `myAttack` brute-forces collisions within a bounded time budget and returns `YES` only if none are found (default budget ≈1 s on a modern laptop).

---

## Extending the exercises

| Idea                           | Where to start                                                                                                                   |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| Swap AES for ChaCha20-Poly1305 | Adapt `aes_mode.py` to use `Cipher(algorithms.ChaCha20, ...)` and re-evaluate the attack surface.                                |
| Incremental hashing            | Replace the one-shot SHA call with the `hashlib` incremental API, then recreate the length-extension attack in `custom_hash.py`. |
| Performance benchmarking       | Time 10⁶ encryptions with PyPy vs CPython and visualise with Matplotlib.                                                         |
| Fuzzing                        | Pipe random keys/IVs/inputs through `aes_mode.Encrypt→Decrypt` round-trip with `hypothesis` to prove correctness.                |

---

## Security disclaimer

The code is **for educational use only**. The custom AES mode and the truncated hash are intentionally weak; do **not** deploy them in production.

---
