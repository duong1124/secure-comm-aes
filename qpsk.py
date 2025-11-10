import numpy as np
from math import sqrt


class QPSK:
    def __init__(self, samples_per_bit: int = 100, carrier_freq: float = 1.0, bit_duration: float = 1.0):
        """
        Args:
            samples_per_bit: Number of samples per bit period
            carrier_freq: Carrier frequency (Hz)
            bit_duration: Bit duration (seconds)
        """
        self.samples_per_bit = samples_per_bit
        self.fc = carrier_freq
        self.tb = bit_duration

        # Generate time vector for one bit period
        self.t = np.linspace(0, self.tb, self.samples_per_bit)

        # Generate carrier waves
        self.c1 = sqrt(2 / self.tb) * np.cos(2 * np.pi * self.fc * self.t)  # I (In-phase)
        self.c2 = sqrt(2 / self.tb) * np.sin(2 * np.pi * self.fc * self.t)  # Q (Quadrature)

    def modulate(self, bits: list) -> np.ndarray:
        """
        Modulate a list of bits using QPSK.

        Args:
            bits: List of bits [0, 1, 1, 0, ...]

        Returns:
            np.ndarray: QPSK modulated signal
        """
        if len(bits) % 2 != 0:
            # Pad with 0 if odd number of bits
            bits = bits + [0]

        num_symbols = len(bits) // 2
        signal = np.zeros(num_symbols * self.samples_per_bit)

        for i in range(0, len(bits), 2):
            symbol_idx = i // 2
            start_idx = symbol_idx * self.samples_per_bit
            end_idx = start_idx + self.samples_per_bit

            # Get odd and even bits
            bit_i = bits[i]  # Odd bit (I-channel)
            bit_q = bits[i + 1]  # Even bit (Q-channel)

            # Map bits to +1 or -1
            m_i = 1 if bit_i == 1 else -1
            m_q = 1 if bit_q == 1 else -1

            # QPSK modulation: s(t) = m_i * c1(t) + m_q * c2(t)
            signal[start_idx:end_idx] = m_i * self.c1 + m_q * self.c2

        return signal

    def demodulate(self, signal: np.ndarray) -> list:
        """
        Demodulate a QPSK signal back to bits.

        Args:
            signal: Received QPSK signal (possibly with noise)

        Returns:
            list: Demodulated bits [0, 1, 1, 0, ...]
        """
        num_symbols = len(signal) // self.samples_per_bit
        bits = []

        for i in range(num_symbols):
            start_idx = i * self.samples_per_bit
            end_idx = start_idx + self.samples_per_bit
            symbol_signal = signal[start_idx:end_idx]

            # Correlate with basis functions
            x_i = np.sum(symbol_signal * self.c1)  # I-channel correlation
            x_q = np.sum(symbol_signal * self.c2)  # Q-channel correlation

            # Decision: if correlation > 0, bit = 1, else bit = 0
            bit_i = 1 if x_i > 0 else 0
            bit_q = 1 if x_q > 0 else 0

            bits.extend([bit_i, bit_q])

        return bits

    def get_constellation_points(self, signal: np.ndarray) -> tuple:
        """
        Get constellation points (I, Q) for visualization.

        Args:
            signal: Modulated signal

        Returns:
            tuple: (I_points, Q_points)
        """
        num_symbols = len(signal) // self.samples_per_bit
        I_points = []
        Q_points = []

        for i in range(num_symbols):
            start_idx = i * self.samples_per_bit
            end_idx = start_idx + self.samples_per_bit
            symbol_signal = signal[start_idx:end_idx]

            x_i = np.sum(symbol_signal * self.c1)
            x_q = np.sum(symbol_signal * self.c2)

            I_points.append(x_i)
            Q_points.append(x_q)

        return np.array(I_points), np.array(Q_points)


def qpsk_modulate(bits: list, samples_per_bit: int = 100, carrier_freq: float = 1.0,
                  bit_duration: float = 1.0) -> np.ndarray:
    modulator = QPSK(samples_per_bit, carrier_freq, bit_duration)
    return modulator.modulate(bits)


def qpsk_demodulate(signal: np.ndarray, samples_per_bit: int = 100,
                    carrier_freq: float = 1.0, bit_duration: float = 1.0) -> list:
    demodulator = QPSK(samples_per_bit, carrier_freq, bit_duration)
    return demodulator.demodulate(signal)