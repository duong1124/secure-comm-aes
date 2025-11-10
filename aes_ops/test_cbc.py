from aes import AES
from .aes_cbc import AES_CBC, encrypt_cbc, decrypt_cbc


def test_basic_cbc():
    """Test basic CBC encryption/decryption"""
    print("=" * 60)
    print("TEST 1: Basic AES-CBC Encryption/Decryption")
    print("=" * 60)

    # Test data
    plaintext = b"Hello World! This is a test message for AES-CBC."
    key = b"SecretKey1234567"  # 16 bytes for AES-128

    print(f"\nOriginal plaintext: {plaintext}")
    print(f"Key: {key}")
    print(f"Key size: {len(key)} bytes (AES-{len(key) * 8})")

    # Method 1: Using convenience functions
    print("\n--- Using convenience functions ---")
    ciphertext, iv = encrypt_cbc(plaintext, key)
    print(f"IV: {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")

    decrypted = decrypt_cbc(ciphertext, key, iv)
    print(f"Decrypted: {decrypted}")

    assert plaintext == decrypted, "Decryption failed!"
    print("✓ Encryption/Decryption successful!")


def test_with_aes_instance():
    """Test CBC using AES instance directly"""
    print("\n" + "=" * 60)
    print("TEST 2: Using AES instance directly")
    print("=" * 60)

    # Create AES instance
    key_size = 16  # 16 bytes = AES-128
    aes = AES(key_size)

    # Create CBC mode with this AES instance
    aes_cbc = AES_CBC(aes)

    plaintext = b"Testing with AES instance!"
    key = b"MySecretKey12345"

    print(f"\nPlaintext: {plaintext}")
    print(f"Key: {key}")

    # Encrypt
    ciphertext, iv = aes_cbc.encrypt(plaintext, key)
    print(f"\nIV: {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decrypt
    decrypted = aes_cbc.decrypt(ciphertext, key, iv)
    print(f"Decrypted: {decrypted}")

    assert plaintext == decrypted, "Decryption failed!"
    print("✓ Success!")


def test_different_key_sizes():
    """Test CBC with different AES key sizes"""
    print("\n" + "=" * 60)
    print("TEST 3: Different Key Sizes (AES-128, AES-192, AES-256)")
    print("=" * 60)

    plaintext = b"Testing different key sizes"

    key_configs = [
        (16, b"SecretKey1234567", "AES-128"),  # 128 bits
        (24, b"SecretKey123456789012345", "AES-192"),  # 192 bits
        (32, b"SecretKey12345678901234567890ABC", "AES-256"),  # 256 bits
    ]

    for key_size, key, name in key_configs:
        print(f"\n--- Testing {name} ---")

        # Create AES instance with specific key size
        aes = AES(key_size)
        aes_cbc = AES_CBC(aes)

        # Encrypt
        ciphertext, iv = aes_cbc.encrypt(plaintext, key)
        print(f"Ciphertext: {ciphertext.hex()[:40]}...")

        # Decrypt
        decrypted = aes_cbc.decrypt(ciphertext, key, iv)

        assert plaintext == decrypted, f"{name} decryption failed!"
        print(f"✓ {name} works correctly!")


def test_long_message():
    """Test with longer message (multiple blocks)"""
    print("\n" + "=" * 60)
    print("TEST 4: Long Message (Multiple Blocks)")
    print("=" * 60)

    # Create a long message
    plaintext = b"A" * 100 + b"B" * 100 + b"C" * 100
    key = b"LongMessageKey!!"

    print(f"\nPlaintext length: {len(plaintext)} bytes")
    print(f"Number of AES blocks: {(len(plaintext) + 15) // 16}")

    # Encrypt
    ciphertext, iv = encrypt_cbc(plaintext, key)
    print(f"Ciphertext length: {len(ciphertext)} bytes")

    # Decrypt
    decrypted = decrypt_cbc(ciphertext, key, iv)
    print(f"Decrypted length: {len(decrypted)} bytes")

    assert plaintext == decrypted, "Long message decryption failed!"
    print("✓ Long message handled correctly!")


def test_custom_iv():
    """Test with custom IV"""
    print("\n" + "=" * 60)
    print("TEST 5: Custom IV")
    print("=" * 60)

    plaintext = b"Test with custom IV"
    key = b"CustomIVKey12345"
    custom_iv = b"MyCustomIV123456"  # 16 bytes

    print(f"\nCustom IV: {custom_iv.hex()}")

    # Encrypt with custom IV
    ciphertext, iv = encrypt_cbc(plaintext, key, custom_iv)

    assert iv == custom_iv, "IV mismatch!"
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decrypt
    decrypted = decrypt_cbc(ciphertext, key, iv)

    assert plaintext == decrypted, "Decryption with custom IV failed!"
    print("✓ Custom IV works correctly!")


def test_empty_and_small():
    """Test edge cases: empty and small messages"""
    print("\n" + "=" * 60)
    print("TEST 6: Edge Cases (Small Messages)")
    print("=" * 60)

    key = b"EdgeCaseKey12345"

    test_cases = [
        (b"", "Empty message"),
        (b"A", "Single byte"),
        (b"AB", "Two bytes"),
        (b"0123456789ABCDE", "15 bytes (one byte less than block)"),
        (b"0123456789ABCDEF", "16 bytes (exactly one block)"),
        (b"0123456789ABCDEFG", "17 bytes (one block + 1 byte)"),
    ]

    for plaintext, description in test_cases:
        print(f"\n--- {description} ---")
        print(f"Plaintext length: {len(plaintext)} bytes")

        ciphertext, iv = encrypt_cbc(plaintext, key)
        decrypted = decrypt_cbc(ciphertext, key, iv)

        assert plaintext == decrypted, f"Failed for {description}"
        print(f"✓ Passed!")


if __name__ == "__main__":
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 15 + "AES-CBC MODE TEST SUITE" + " " * 20 + "║")
    print("╚" + "=" * 58 + "╝")

    try:
        test_basic_cbc()
        test_with_aes_instance()
        test_different_key_sizes()
        test_long_message()
        test_custom_iv()
        test_empty_and_small()

        print("\n" + "=" * 60)
        print("✓ ALL TESTS PASSED!")
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}\n")
        raise