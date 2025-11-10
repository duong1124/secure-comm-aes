import numpy as np
import matplotlib.pyplot as plt


def text_to_bits(text: str, encoding: str = 'utf-8') -> list:
    return bytes_to_bits(text_to_bytes(text, encoding))


def bits_to_text(bits: list, encoding: str = 'utf-8') -> str:
    return bytes_to_text(bits_to_bytes(bits), encoding)


def text_to_bytes(text: str, encoding: str = 'utf-8') -> bytes:
    return text.encode(encoding)


def bytes_to_text(data: bytes, encoding: str = 'utf-8') -> str:
    return data.decode(encoding, errors='ignore')


def bytes_to_bits(data: bytes) -> list:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):  # MSB first
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list) -> bytes:
    """ Convert a list of bits to bytes."""
    # Pad bits to multiple of 8
    if len(bits) % 8 != 0:
        bits = bits + [0] * (8 - len(bits) % 8)

    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        byte_array.append(byte)

    return bytes(byte_array)


def calculate_ber(original_bits: list, received_bits: list) -> float:
    if len(original_bits) != len(received_bits):
        # Truncate to shorter length
        min_len = min(len(original_bits), len(received_bits))
        original_bits = original_bits[:min_len]
        received_bits = received_bits[:min_len]

    errors = sum(1 for o, r in zip(original_bits, received_bits) if o != r)
    total_bits = len(original_bits)

    return errors / total_bits if total_bits > 0 else 0


def plot_ber_vs_snr(snr_list: list, ber_list: list, title: str = "BER vs SNR",
                    save_path: str = None):
    """
    Plot BER vs SNR curve.

    Args:
        snr_list: List of SNR values (in dB)
        ber_list: List of corresponding BER values
        title: Plot title
        save_path: Path to save figure (optional)
    """
    plt.figure(figsize=(10, 6))
    plt.semilogy(snr_list, ber_list, 'b-o', linewidth=2, markersize=8)
    plt.grid(True, which='both', linestyle='--', alpha=0.6)
    plt.xlabel('SNR (dB)', fontsize=12)
    plt.ylabel('Bit Error Rate (BER)', fontsize=12)
    plt.title(title, fontsize=14)
    plt.xlim([min(snr_list), max(snr_list)])

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')

    plt.show()


def plot_constellation(I_points: np.ndarray, Q_points: np.ndarray,
                       title: str = "QPSK Constellation", save_path: str = None):
    """
    Plot constellation diagram.

    Args:
        I_points: In-phase component values
        Q_points: Quadrature component values
        title: Plot title
        save_path: Path to save figure (optional)
    """
    plt.figure(figsize=(8, 8))
    plt.scatter(I_points, Q_points, alpha=0.6, s=50)
    plt.grid(True, alpha=0.3)
    plt.axhline(y=0, color='k', linewidth=0.5)
    plt.axvline(x=0, color='k', linewidth=0.5)
    plt.xlabel('In-Phase (I)', fontsize=12)
    plt.ylabel('Quadrature (Q)', fontsize=12)
    plt.title(title, fontsize=14)
    plt.axis('equal')

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')

    plt.show()


def plot_signal(signal: np.ndarray, title: str = "Signal",
                sample_rate: float = 1.0, max_samples: int = 1000,
                save_path: str = None):
    """
    Plot time-domain signal.

    Args:
        signal: Signal to plot
        title: Plot title
        sample_rate: Sample rate for time axis
        max_samples: Maximum number of samples to plot
        save_path: Path to save figure (optional)
    """
    # Limit number of samples for visualization
    signal_plot = signal[:max_samples]
    time = np.arange(len(signal_plot)) / sample_rate

    plt.figure(figsize=(12, 4))
    plt.plot(time, signal_plot, linewidth=1)
    plt.grid(True, alpha=0.3)
    plt.xlabel('Time', fontsize=12)
    plt.ylabel('Amplitude', fontsize=12)
    plt.title(title, fontsize=14)

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')

    plt.show()


def print_comparison(original_bits: list, received_bits: list, max_bits: int = 100):
    """
    Print comparison of original and received bits.

    Args:
        original_bits: Original bits
        received_bits: Received bits
        max_bits: Maximum number of bits to display
    """
    print("\n" + "=" * 60)
    print("BIT COMPARISON")
    print("=" * 60)

    min_len = min(len(original_bits), len(received_bits), max_bits)
    errors = 0

    print(f"Showing first {min_len} bits:\n")
    print("Original : ", end="")
    for i in range(min_len):
        print(original_bits[i], end="")
    print()

    print("Received : ", end="")
    for i in range(min_len):
        print(received_bits[i], end="")
    print()

    print("Errors   : ", end="")
    for i in range(min_len):
        if original_bits[i] != received_bits[i]:
            print("^", end="")
            errors += 1
        else:
            print(" ", end="")
    print()

    ber = calculate_ber(original_bits, received_bits)
    print(f"\nTotal Errors: {errors}/{len(original_bits)}")
    print(f"BER: {ber:.6f} ({ber * 100:.4f}%)")
    print("=" * 60 + "\n")