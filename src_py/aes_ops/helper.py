def xor_bytes(a: bytes, b: bytes):
    return bytes([x ^ y for x, y in zip(a, b)])


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS#7 padding to data."""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(padded_text: bytes) -> bytes:
    """Remove PKCS#7 padding from data."""
    padding_length = padded_text[-1]
    if padding_length > len(padded_text) or padding_length == 0:
        raise ValueError("Invalid padding")
    # Verify padding
    if padded_text[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding")
    return padded_text[:-padding_length]