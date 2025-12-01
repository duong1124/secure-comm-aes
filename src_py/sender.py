# from src_py.aes_ops import encrypt_cbc

# def main():
#     key = b"thisisakey123456"

#     message = input("Enter plaintext: ")
#     plaintext = message.encode("utf-8")

#     # iv = input("Enter iv:")
#     ciphertext, iv = encrypt_cbc(plaintext, key, iv=None)

#     print("Private key:", key.hex())
#     print("IV  (public):   ", iv.hex())
#     print("Ciphertext (public)", ciphertext.hex())

# if __name__ == "__main__":
#     main()
from src_py.aes_ops.aes_ecb import encrypt_ecb

def main():
    # 16-byte key (giống AES-128)
    key = b"thisisakey123456"

    # Nhập plaintext từ người dùng
    message = input("Enter plaintext: ")
    plaintext = message.encode("utf-8")

    # ECB không dùng IV, nên chỉ cần ciphertext
    ciphertext = encrypt_ecb(key, plaintext)

    print("Private key:            ", key.hex())
    print("Ciphertext (public):    ", ciphertext.hex())

if __name__ == "__main__":
    main()