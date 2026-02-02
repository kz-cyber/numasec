# Cryptography Cheatsheet

## Hash Identification
- **MD5:** 32 hex chars (e.g., `5d41402abc4b2a76b9719d911017c592`)
- **SHA1:** 40 hex chars
- **SHA256:** 64 hex chars
- **NTLM:** 32 hex chars (Windows)
- **Bcrypt:** Starts with `$2a$`, `$2b$`, or `$2y$` (e.g., `$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy`)

## Classic Ciphers
- **Caesar Cipher:** Shift letters (ROT13 is shift 13).
- **Vigenère:** Polyalphabetic substitution using a keyword.
- **Atbash:** Reverse alphabet (A->Z, B->Y).
- **Substitution:** Random mapping.
- **Tool:** [CyberChef](https://gchq.github.io/CyberChef/) or `quipqiup.com` (for substitution).

## RSA Attacks
- **Small e (e=3):** Cube Root Attack.
- **Small N:** Factorize N using `factordb.com`.
- **Common Modulus:** Same N, different e1, e2.
- **Wiener's Attack:** Small d (private exponent).
- **Tool:** `RsaCtfTool`

## XOR
- **Properties:**
  - `A ^ A = 0`
  - `A ^ 0 = A`
  - `A ^ B = C` => `A ^ C = B`
- **Known Plaintext Attack:** If you know the start of the file (e.g., `PNG` header), XOR it with the ciphertext to find the key.

## Padding Oracle Attack (CBC Mode)
If the server reveals if padding is correct/incorrect:
- **Tool:** `padbuster`
- **Command:** `padbuster URL EncryptedSample BlockSize [options]`

## Hash Length Extension Attack
If `H(secret + message)` is used:
- **Tool:** `hashpump`
- **Usage:** Append data to the message without knowing the secret.

## Bit Flipping (CBC Mode)
- Modifying a byte in the ciphertext block `N` affects the decrypted plaintext in block `N+1`.
- `P'[i] = P[i] ^ C[i] ^ C'[i]`
- To change `P[i]` to `X`: `C'[i] = C[i] ^ P[i] ^ X`

```