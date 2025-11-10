from aes import AES

input_bytes = bytearray(b"exampleplaintext") # 16 bytes
key = bytearray(b"thisisakey123456")         # 16 bytes
key_size = len(key)                          # Key size in bytes

aes = AES(key_size)

encrypted_data = aes.encrypt(input_bytes, key)
print("Encrypted:", encrypted_data)

decrypted_data = aes.decrypt(encrypted_data, key)
print("Decrypted:", decrypted_data)