from src_py.aes_ops.helper import xor_bytes, pkcs7_pad, pkcs7_unpad


def encrypt_ecb(key, plaintext):
   block_size = len(key)
   padded_plaintext = pkcs7_pad(plaintext, block_size)
   num_blocks = len(padded_plaintext) // block_size

   cipher_text = b''
   for i in range(num_blocks):
      block_start = i * block_size
      block_end = block_start + block_size
      block = padded_plaintext[block_start:block_end]

      encrypted_block = xor_bytes(block, key)
      cipher_text += encrypted_block

   return cipher_text


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

   return pkcs7_unpad(plain_text)
