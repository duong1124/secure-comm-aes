from aes_ops import decrypt_cbc

def main():
    key_hex = input("Enter key (hex): ").strip()
    iv_hex = input("Enter IV (hex): ").strip()
    ct_hex = input("Enter ciphertext (hex): ").strip()

    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ct_hex)

    try:
        plaintext = decrypt_cbc(ciphertext, key, iv)
        print("\nDecrypted text:")
        print(plaintext.decode("utf-8"))
    except Exception as e:
        print(f"\nDecryption failed (wrong key or error).\n{e}")

if __name__ == "__main__":
    main()
