# ECB encryption & decryption
def padding(text, block_size):
   padding_length = block_size - (len(text) % block_size)
   padding = bytes([padding_length] * padding_length)
   return text + padding

def unpadding(padded_text):
   padding_length = padded_text[-1]
   return padded_text[:-padding_length]

def xor_bytes(byte1, byte2):
   return bytes([a ^ b for a, b in zip(byte1, byte2)])
#Encryption Method
def encrypt_ecb(key, plaintext):
   block_size = len(key)
   padded_plaintext = padding(plaintext, block_size)
   num_blocks = len(padded_plaintext) // block_size

   cipher_text = b''
   for i in range(num_blocks):
      block_start = i * block_size
      block_end = block_start + block_size
      block = padded_plaintext[block_start:block_end]

      encrypted_block = xor_bytes(block, key)
      cipher_text += encrypted_block

   return cipher_text
# Decryption Method
def decrypt_ecb(key, ciphertext):
   block_size = len(key)
   num_blocks = len(ciphertext) // block_size

   plain_text = b''
   for i in range(num_blocks):
      block_start = i * block_size
      block_end = block_start + block_size
      block = ciphertext[block_start:block_end]

      decrypted_block = xor_bytes(block, key)
      plain_text += decrypted_block

   return unpadding(plain_text)

# key and plaintext
# key = b'ABCDEFGHIJKLMNOP'  # 16 bytes key for AES-128
# plaintext = b'Hello, This is superman!'
# ciphertext = encrypt_ecb(key, plaintext)
# print("Ciphertext:", ciphertext)
# decrypted_plaintext = decrypt_ecb(key, ciphertext)
# print("Decrypted plaintext:", decrypted_plaintext.decode('utf-8'))