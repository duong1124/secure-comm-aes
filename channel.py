from __future__ import annotations
import numpy as np

def calculate_signal_power(signal: np.ndarray) -> float:
    """Average power E[|x|^2]"""
    sig = np.asarray(signal)
    return float(np.mean(np.abs(sig) ** 2))

def add_awgn_noise(signal: np.ndarray, snr_db: float, rng=None) -> np.ndarray:
    """
    Thêm AWGN để đạt SNR (dB) tại ĐẦU VÀO HÀM (tức là sau khi bạn đã áp fading nếu gọi sau).
    - Nếu signal là phức: nhiễu CN(0, sigma^2), var mỗi nhánh I/Q = noise_power/2.
    """
    if snr_db is None:
        return signal

    sig = np.asarray(signal)
    p_sig = calculate_signal_power(sig)
    eps = 1e-15
    if p_sig < eps:
        p_sig = eps  # tránh NaN nếu công suất ~0

    snr_linear = 10.0 ** (snr_db / 10.0)
    noise_power = p_sig / snr_linear

    rng = np.random.default_rng(rng)
    if np.iscomplexobj(sig):
        std = np.sqrt(noise_power / 2.0)
        noise = rng.normal(0.0, std, sig.shape) + 1j * rng.normal(0.0, std, sig.shape)
    else:
        std = np.sqrt(noise_power)
        noise = rng.normal(0.0, std, sig.shape)

    return sig + noise

def _expand_block_coeffs(h_blocks: np.ndarray, N: int, sps: int) -> np.ndarray:
    """Lặp hệ số kênh theo block (mỗi block = 1 symbol) ra từng mẫu và cắt đúng N."""
    return np.repeat(h_blocks, sps)[:N]

def apply_rayleigh_fading(signal: np.ndarray, samples_per_symbol: int = 100,
                          rng=None, return_h: bool = False) -> np.ndarray | tuple:
    """
    Rayleigh flat fading chậm: h ~ CN(0,1) theo từng symbol, giữ h không đổi trong 1 symbol.
    Trả về y = h * x (phức). Có thể trả về cả h theo mẫu để equalization.
    """
    sig = np.asarray(signal)
    N = sig.size
    n_blocks = int(np.ceil(N / samples_per_symbol))

    rng = np.random.default_rng(rng)
    h_blocks = (rng.normal(0, 1/np.sqrt(2), n_blocks)
                + 1j * rng.normal(0, 1/np.sqrt(2), n_blocks))  # CN(0,1)

    h = _expand_block_coeffs(h_blocks, N, samples_per_symbol)
    y = sig.astype(np.complex128) * h
    return (y, h) if return_h else y

def apply_rician_fading(signal: np.ndarray, k_factor_db: float = 10.0,
                        samples_per_symbol: int = 100, rng=None,
                        los_phase: str = "random", return_h: bool = False) -> np.ndarray | tuple:
    """
    Rician flat fading: h = sqrt(K/(K+1)) * e^{jθ} + (1/sqrt(K+1)) * n, n~CN(0,1).
    - los_phase: 'random' (mỗi symbol một pha) hoặc 'zero' (pha 0).
    """
    sig = np.asarray(signal)
    N = sig.size
    n_blocks = int(np.ceil(N / samples_per_symbol))
    k_lin = 10.0 ** (k_factor_db / 10.0)

    rng = np.random.default_rng(rng)
    if los_phase == "random":
        theta = rng.uniform(0.0, 2*np.pi, n_blocks)
        los = np.sqrt(k_lin/(k_lin+1)) * np.exp(1j * theta)
    else:
        los = np.full(n_blocks, np.sqrt(k_lin/(k_lin+1)), dtype=np.complex128)

    scatter = ((rng.normal(0, 1/np.sqrt(2), n_blocks)
                + 1j * rng.normal(0, 1/np.sqrt(2), n_blocks)) / np.sqrt(k_lin + 1.0))

    h_blocks = los + scatter
    h = _expand_block_coeffs(h_blocks, N, samples_per_symbol)
    y = sig.astype(np.complex128) * h
    return (y, h) if return_h else y

class WirelessChannel:
    def __init__(self, samples_per_symbol: int = 100, rng=None):
        """
        samples_per_symbol (sps): số mẫu trên 1 symbol (slow fading giữ h cố định trong 1 symbol).
        rng: seed (int) hoặc Generator để tái lập.
        """
        self.samples_per_symbol = samples_per_symbol
        self.rng = rng

    def transmit(self, signal: np.ndarray, snr_db: float | None = None,
                 fading: str | None = None, k_factor_db: float = 10.0,
                 return_h: bool = False, los_phase: str = "random") -> np.ndarray | tuple:
        """
        Truyền qua kênh phẳng (flat), slow-fading theo symbol:
        - fading: None | 'rayleigh' | 'rician'
        - snr_db: SNR tại phía thu (sau khi áp fading).
        - return_h: nếu True, trả (y, h_per_sample) để tiện equalization.
        """
        y = np.asarray(signal)
        h = None

        if fading == 'rayleigh':
            y, h = apply_rayleigh_fading(y, self.samples_per_symbol, rng=self.rng, return_h=True)
        elif fading == 'rician':
            y, h = apply_rician_fading(y, k_factor_db, self.samples_per_symbol,
                                       rng=self.rng, los_phase=los_phase, return_h=True)

        y = add_awgn_noise(y, snr_db, rng=self.rng) if snr_db is not None else y
        return (y, h) if return_h else y

# --------- tiện ích test nhanh ----------
def measure_snr_db(clean: np.ndarray, noisy: np.ndarray) -> float:
    """Đo SNR dB từ cặp (clean, noisy) theo định nghĩa 10log10(Ps/Pn)."""
    s = np.asarray(clean)
    y = np.asarray(noisy)
    n = y - s
    ps = calculate_signal_power(s)
    pn = calculate_signal_power(n)
    return 10.0 * np.log10(ps / max(pn, 1e-15))
