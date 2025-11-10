from aes_ops import encrypt_cbc, decrypt_cbc
from qpsk import QPSK
from channel import WirelessChannel
from utils import (text_to_bytes, bytes_to_text, bytes_to_bits, bits_to_bytes,
                   calculate_ber, plot_ber_vs_snr, plot_constellation,
                   plot_signal, print_comparison)
import numpy as np


def main():
    print("=" * 70)
    print("AES-CBC + QPSK WIRELESS COMMUNICATION SYSTEM")
    print("=" * 70)

    # ==================== CONFIGURATION ====================
    # Message
    message = "Hello QPSK! This is a secure wireless transmission using AES-CBC encryption."
    print(f"\nOriginal Message:\n'{message}'")
    print(f"Message Length: {len(message)} characters")

    # AES Key (16 bytes for AES-128)
    key = b"SecretKey1234567"  # 16 bytes
    print(f"\nAES Key: {key}")

    # QPSK parameters
    samples_per_bit = 100
    carrier_freq = 1.0
    bit_duration = 1.0

    # Channel parameters
    snr_db = 15  # Signal-to-Noise Ratio in dB
    print(f"Channel SNR: {snr_db} dB")

    # ==================== TRANSMITTER ====================
    print("\n" + "=" * 70)
    print("TRANSMITTER")
    print("=" * 70)

    # Step 1: Convert message to bytes
    plaintext_bytes = text_to_bytes(message)
    print(f"\n1. Text to Bytes: {len(plaintext_bytes)} bytes")

    # Step 2: Encrypt with AES-CBC
    ciphertext, iv = encrypt_cbc(plaintext_bytes, key)
    print(f"2. AES-CBC Encryption: {len(ciphertext)} bytes ciphertext")
    print(f"   IV: {iv.hex()}")

    # Step 3: Convert ciphertext to bits
    cipher_bits = bytes_to_bits(ciphertext)
    print(f"3. Bytes to Bits: {len(cipher_bits)} bits")

    # Step 4: QPSK Modulation
    qpsk = QPSK(samples_per_bit, carrier_freq, bit_duration)
    modulated_signal = qpsk.modulate(cipher_bits)
    print(f"4. QPSK Modulation: {len(modulated_signal)} samples")

    # ==================== CHANNEL ====================
    print("\n" + "=" * 70)
    print("WIRELESS CHANNEL")
    print("=" * 70)

    # Transmit through wireless channel with AWGN
    channel = WirelessChannel(samples_per_bit)
    received_signal = channel.transmit(modulated_signal, snr_db=snr_db)
    print(f"\nSignal transmitted through AWGN channel (SNR = {snr_db} dB)")

    # ==================== RECEIVER ====================
    print("\n" + "=" * 70)
    print("RECEIVER")
    print("=" * 70)

    # Step 5: QPSK Demodulation
    demodulated_bits = qpsk.demodulate(received_signal)
    print(f"\n5. QPSK Demodulation: {len(demodulated_bits)} bits recovered")

    # Step 6: Convert bits to bytes
    received_ciphertext = bits_to_bytes(demodulated_bits)
    # Truncate to original ciphertext length (in case padding was added)
    received_ciphertext = received_ciphertext[:len(ciphertext)]
    print(f"6. Bits to Bytes: {len(received_ciphertext)} bytes")

    # Step 7: Decrypt with AES-CBC
    try:
        decrypted_bytes = decrypt_cbc(received_ciphertext, key, iv)
        decrypted_message = bytes_to_text(decrypted_bytes)
        print(f"7. AES-CBC Decryption: Success!")
    except Exception as e:
        decrypted_message = "[DECRYPTION FAILED]"
        print(f"7. AES-CBC Decryption: FAILED - {e}")

    # ==================== RESULTS ====================
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    print(f"\nDecrypted Message:\n'{decrypted_message}'")

    # Calculate BER
    ber = calculate_ber(cipher_bits, demodulated_bits)
    print(f"\nBit Error Rate (BER): {ber:.6f} ({ber * 100:.4f}%)")

    # Message comparison
    if message == decrypted_message:
        print("\n✓ SUCCESS: Message transmitted correctly!")
    else:
        print("\n✗ ERROR: Message corrupted during transmission")
        print(f"  Match: {sum(c1 == c2 for c1, c2 in zip(message, decrypted_message))}/{len(message)} characters")

    # ==================== VISUALIZATIONS ====================
    print("\n" + "=" * 70)
    print("GENERATING PLOTS...")
    print("=" * 70)

    # Plot modulated signal (first 1000 samples)
    plot_signal(modulated_signal, title="QPSK Modulated Signal (Clean)",
                max_samples=1000)

    # Plot received signal with noise
    plot_signal(received_signal, title=f"Received Signal (SNR = {snr_db} dB)",
                max_samples=1000)

    # Plot constellation diagram
    I_points, Q_points = qpsk.get_constellation_points(received_signal)
    plot_constellation(I_points, Q_points,
                       title=f"QPSK Constellation (SNR = {snr_db} dB)")

    # Print bit comparison (first 100 bits)
    print_comparison(cipher_bits, demodulated_bits, max_bits=100)


def ber_vs_snr_simulation():
    """
    Simulate BER vs SNR for different noise levels.
    """
    print("\n" + "=" * 70)
    print("BER vs SNR SIMULATION")
    print("=" * 70)

    # Test message
    message = "Test message for BER simulation."
    key = b"SecretKey1234567"

    # SNR range
    snr_range = np.arange(0, 21, 2)  # 0 to 20 dB, step 2
    ber_list = []

    # QPSK setup
    qpsk = QPSK(samples_per_bit=100, carrier_freq=1.0, bit_duration=1.0)
    channel = WirelessChannel(samples_per_bit=100)

    print(f"\nTesting SNR range: {snr_range[0]} to {snr_range[-1]} dB")
    print("Running simulations...")

    for snr_db in snr_range:
        # Encrypt and modulate
        plaintext_bytes = text_to_bytes(message)
        ciphertext, iv = encrypt_cbc(plaintext_bytes, key)
        cipher_bits = bytes_to_bits(ciphertext)
        modulated_signal = qpsk.modulate(cipher_bits)

        # Transmit through channel
        received_signal = channel.transmit(modulated_signal, snr_db=snr_db)

        # Demodulate
        demodulated_bits = qpsk.demodulate(received_signal)

        # Calculate BER
        ber = calculate_ber(cipher_bits, demodulated_bits)
        ber_list.append(ber)

        print(f"  SNR = {snr_db:2d} dB -> BER = {ber:.6f}")

    # Plot results
    plot_ber_vs_snr(snr_range, ber_list,
                    title="BER vs SNR for AES-CBC + QPSK System")

    print("\nSimulation complete!")


if __name__ == "__main__":
    # Run main demo
    main()

    # Uncomment to run BER vs SNR simulation
    # print("\n" * 3)
    # ber_vs_snr_simulation()