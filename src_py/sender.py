# from src_py.aes_ops import encrypt_cbc
from src_py.aes_ops import encrypt_ecb

def main():
    key = b"thisisakey123456"

    message = input("Enter plaintext: ")
    plaintext = message.encode("utf-8")

   # iv = input("Enter iv:")
   # ciphertext, iv = encrypt_cbc(plaintext, key, iv=None)
    ciphertext = encrypt_ecb(key, plaintext)

    print("Private key:            ", key.hex())
    # print("IV (public):            ", iv.hex())
    print("Ciphertext (public):    ", ciphertext.hex())

if __name__ == "__main__":
    main()