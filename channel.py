import numpy as np


def calculate_signal_power(signal: np.ndarray) -> float:
    """Calculate average power."""
    return np.mean(np.abs(signal) ** 2)


def add_awgn_noise(signal: np.ndarray, snr_db: float) -> np.ndarray:
    """
    Returns:
        np.ndarray: Noisy signal
    """
    signal_power = calculate_signal_power(signal)

    snr_linear = 10 ** (snr_db / 10)

    noise_power = signal_power / snr_linear

    # Generate noise with calculated power
    noise_std = np.sqrt(noise_power)
    noise = np.random.normal(0, noise_std, signal.shape)

    # Add noise to signal
    noisy_signal = signal + noise

    return noisy_signal


def apply_rayleigh_fading(signal: np.ndarray, samples_per_symbol: int = 100) -> np.ndarray:
    """
    Apply Rayleigh fading to a signal.

    Rayleigh fading models non-line-of-sight propagation with multiple reflections.

    Args:
        signal: Clean signal
        samples_per_symbol: Number of samples per symbol (for slow fading)

    Returns:
        np.ndarray: Signal with Rayleigh fading
    """
    num_symbols = len(signal) // samples_per_symbol
    faded_signal = np.copy(signal)

    for i in range(num_symbols):
        # Generate Rayleigh fading coefficient for this symbol
        # Rayleigh distributed amplitude
        h_real = np.random.normal(0, 1 / np.sqrt(2))
        h_imag = np.random.normal(0, 1 / np.sqrt(2))
        h = h_real + 1j * h_imag
        h_amplitude = np.abs(h)

        # Apply fading to the entire symbol
        start_idx = i * samples_per_symbol
        end_idx = start_idx + samples_per_symbol
        faded_signal[start_idx:end_idx] *= h_amplitude

    return faded_signal


def apply_rician_fading(signal: np.ndarray, k_factor_db: float = 10,
                        samples_per_symbol: int = 100) -> np.ndarray:
    """
    Apply Rician fading to a signal.

    Rician fading models propagation with a dominant line-of-sight path plus reflections.

    Args:
        signal: Clean signal
        k_factor_db: Rician K-factor in dB (ratio of LOS to scattered power)
        samples_per_symbol: Number of samples per symbol

    Returns:
        np.ndarray: Signal with Rician fading
    """
    k_linear = 10 ** (k_factor_db / 10)
    num_symbols = len(signal) // samples_per_symbol
    faded_signal = np.copy(signal)

    for i in range(num_symbols):
        # LOS component (dominant path)
        los_component = np.sqrt(k_linear / (k_linear + 1))

        # Scattered component (multiple reflections)
        scatter_real = np.random.normal(0, 1 / np.sqrt(2))
        scatter_imag = np.random.normal(0, 1 / np.sqrt(2))
        scatter_component = (scatter_real + 1j * scatter_imag) / np.sqrt(k_linear + 1)

        # Total channel coefficient
        h = los_component + scatter_component
        h_amplitude = np.abs(h)

        # Apply fading to the entire symbol
        start_idx = i * samples_per_symbol
        end_idx = start_idx + samples_per_symbol
        faded_signal[start_idx:end_idx] *= h_amplitude

    return faded_signal


class WirelessChannel:
    def __init__(self, samples_per_symbol: int = 100):
        self.samples_per_symbol = samples_per_symbol

    def transmit(self, signal: np.ndarray, snr_db: float = None,
                 fading: str = None, k_factor_db: float = 10) -> np.ndarray:
        """
        Transmit signal through wireless channel.

        Args:
            signal: Clean signal
            snr_db: SNR in dB (None for no noise)
            fading: Fading type ('rayleigh', 'rician', or None)
            k_factor_db: Rician K-factor (only used if fading='rician')

        Returns:
            np.ndarray: Received signal
        """
        received_signal = signal.copy()

        # Apply fading if specified
        if fading == 'rayleigh':
            received_signal = apply_rayleigh_fading(received_signal, self.samples_per_symbol)
        elif fading == 'rician':
            received_signal = apply_rician_fading(received_signal, k_factor_db,
                                                  self.samples_per_symbol)

        # Add noise if SNR is specified
        if snr_db is not None:
            received_signal = add_awgn_noise(received_signal, snr_db)

        return received_signal