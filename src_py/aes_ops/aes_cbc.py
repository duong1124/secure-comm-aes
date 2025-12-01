import os

from src_py.aes import AES


class AES_CBC:
    def __init__(self, aes: AES):
        self.aes_cbc = aes
        self.block_size = 16  # AES block size is always 16 bytes

    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes = None) -> tuple:
        """
        Returns:
            tuple: (ciphertext, iv)
        """
        if iv is None:
            iv = os.urandom(self.block_size)

        if len(iv) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} bytes")

        if len(key) != self.aes_cbc.key_size:
            raise ValueError(f"Key must be {self.aes_cbc.key_size} bytes")

        # Pad plaintext to block size
        padded_plaintext = pkcs7_pad(plaintext, self.block_size)

        ciphertext = b''
        previous_block = iv

        # Process each block
        for i in range(0, len(padded_plaintext), self.block_size):
            block = padded_plaintext[i:i + self.block_size]
            # XOR with previous ciphertext block (or IV for first block)
            xored_block = xor_bytes(block, previous_block)
            # Encrypt the XORed block
            encrypted_block = self.aes_cbc.encrypt(bytearray(xored_block))
            ciphertext += bytes(encrypted_block)
            previous_block = encrypted_block

        return ciphertext, iv

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Returns:
            bytes: Decrypted plaintext
        """
        if len(iv) != self.block_size:
            raise ValueError(f"IV must be {self.block_size} bytes")

        if len(key) != self.aes_cbc.key_size:
            raise ValueError(f"Key must be {self.aes_cbc.key_size} bytes")

        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size")

        plaintext = b''
        previous_block = iv

        # Process each block
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            # Decrypt the block
            decrypted_block = self.aes_cbc.decrypt(bytearray(block), bytearray(key))
            # XOR with previous ciphertext block (or IV for first block)
            plaintext_block = xor_bytes(bytes(decrypted_block), previous_block)
            plaintext += plaintext_block
            previous_block = block

        # Remove padding
        return pkcs7_unpad(plaintext)


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes = None) -> tuple:
    aes_instance = AES(key)
    aes_cbc = AES_CBC(aes_instance)
    return aes_cbc.encrypt(plaintext, key, iv)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    aes_instance = AES(key)
    aes_cbc = AES_CBC(aes_instance)
    return aes_cbc.decrypt(ciphertext, key, iv)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS#7 padding to data."""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding from data."""
    if not data:
        raise ValueError("Cannot unpad empty data")
    padding_length = data[-1]
    if padding_length > len(data) or padding_length == 0:
        raise ValueError("Invalid padding")
    # Verify padding
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding")
    return data[:-padding_length]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
