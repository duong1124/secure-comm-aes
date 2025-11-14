# Secure Communication using AES

## `aes`
- AES implementation, an example for its API can be viewed in `example.py`.

## `aes_ops`
- AES mode of operation, each designed for different contexts and security requirements.
- Mode of operation list:
  - `aes_cbc.py` - Cipher Block Chaining mode
  - ...


# Use Case

## Simple
- Encrypt a short text message and send the ciphertext publicly. Only receivers with the correct key can decrypt it.
- Run `sender.py`, take `iv`, `ciphertext` and `key` (hex)
- Receiver runs `receiver.py`, re-enter those three. We would receive the right `plaintext` if entered right `key`, else error or "trash" text.


# Future Directions
- Add more AES modes:
  - CTR, GCM, ...
- Add more types of `plaintext` (e.g., audio/image/...) and theirs utils.
- Add benchmarks and correctness tests.
- Evaluate AES inter-mode of operations by visualizing its decrypted image.
  - How should we evaluate it? By which metrics? At which context/case?
  - How many type/case of image should we evaluate?
- Elevate use case (e.g., end-to-end demo ... )