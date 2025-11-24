from aes import AES

input_bytes = b"exampleplaintext" # 16 bytes
key = b"thisisakey123456"         # 16 bytes                          # Key size in bytes

aes = AES(key)

encrypted_data = aes.encrypt(input_bytes)
print("Encrypted:", encrypted_data)

decrypted_data = aes.decrypt(encrypted_data)
print("Decrypted:", decrypted_data)