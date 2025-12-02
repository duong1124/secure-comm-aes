# from src_py.aes_ops import decrypt_cbc
from src_py.aes_ops import decrypt_ecb

def main():
    key_hex = input("Enter key (hex): ").strip()
    ct_hex = input("Enter ciphertext (hex): ").strip()
#   iv_hex = input("Enter IV (hex): ").strip()

    key = bytes.fromhex(key_hex)
#   iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ct_hex)

    try:
        # plaintext = decrypt_cbc(ciphertext, key, iv)
        plaintext = decrypt_ecb(key, ciphertext)
        print("\nDecrypted text:")
        print(plaintext.decode("utf-8"))
    except Exception as e:
        print(f"\nDecryption failed (wrong key or error):\n{e}")

if __name__ == "__main__":
    main()
