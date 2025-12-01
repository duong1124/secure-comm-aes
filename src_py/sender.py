from src_py.aes_ops import encrypt_cbc

def main():
    key = b"thisisakey123456"

    message = input("Enter plaintext: ")
    plaintext = message.encode("utf-8")

    # iv = input("Enter iv:")
    ciphertext, iv = encrypt_cbc(plaintext, key, iv=None)

    print("Private key:", key.hex())
    print("IV  (public):   ", iv.hex())
    print("Ciphertext (public)", ciphertext.hex())

if __name__ == "__main__":
    main()