# Secure Communication using AES

## `aes`
- AES implementation, an example for its API can be viewed in `example.py`.

## `aes_ops`
- AES mode of operation, each designed for different contexts and security requirements.
- Mode of operation list:
  - `aes_ecb` - Electronic Codebook mode
  - `aes_cbc.py` - Cipher Block Chaining mode
  - `aes_gcm.py` - Galios/Counter mode
---

# Use Case
- Encrypt a short text message and send the ciphertext publicly. Only receivers with the correct key can decrypt it.
- Run `sender.py`, take `iv`, `ciphertext` and `key` (hex).
- Receiver runs `receiver.py`, re-enter those three. We would receive the right `plaintext` if entered right `key`, else error or "trash" text.
---

# How to run

## Python source

- Stands at root dir `aes-secure-comm`, runs file by module with flag `-m`.
- For example, to run `src_py\aes\example.py`.
```bash
python -m src_py.aes.example
```
---

## Matlab source
- Quite straightforward: Copy all files from `src_mat` into a single folder (or add that folder to the MATLAB path).
- In MATLAB (or MATLAB Online), set that folder as current dir and run the desired script (e.g. `sender.m`, `receiver.m`, or `example.m`).