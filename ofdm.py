from __future__ import annotations
import numpy as np

# -------- QPSK (M-PSK với M=4, mapping như MATLAB pskmod) ----------
def pskmod(data: np.ndarray, M: int = 4) -> np.ndarray:
    data = np.asarray(data) % M
    return np.exp(1j * 2 * np.pi * data / M)  # 0,90,180,270 deg (như MATLAB pskmod)

def pskdemod(sym: np.ndarray, M: int = 4) -> np.ndarray:
    ang = np.angle(sym) % (2*np.pi)
    idx = np.round(ang / (2*np.pi/M)) % M
    return idx.astype(int)

# --------- Kênh & nhiễu ----------
def add_awgn(x: np.ndarray, snr_db: float, rng=None) -> np.ndarray:
    rng = np.random.default_rng(rng)
    p_sig = np.mean(np.abs(x)**2)
    snr_lin = 10**(snr_db/10.0)
    p_n = p_sig / snr_lin
    n = np.sqrt(p_n/2)*(rng.standard_normal(x.shape) + 1j*rng.standard_normal(x.shape))
    return x + n

def random_fir_channel(L: int = 2, rng=None) -> np.ndarray:
    """Rayleigh FIR h[0..L-1], chuẩn hóa E[||h||^2]=1."""
    rng = np.random.default_rng(rng)
    h = (rng.standard_normal(L) + 1j*rng.standard_normal(L))/np.sqrt(2)
    h = h / np.sqrt(np.sum(np.abs(h)**2))
    return h

# --------- OFDM ----------
class OFDM:
    """
    OFDM chuẩn: IFFT N_fft, CP dài cp_len.
    active_idx: chỉ số những subcarrier phát (ví dụ 4 subcarriers).
    """
    def __init__(self, N_fft: int = 16, cp_len: int = 2, active_idx: np.ndarray | None = None):
        self.N = N_fft
        self.cp = cp_len
        if active_idx is None:
            # mặc định: 4 subcarrier ở giữa (tránh DC lệch): [-2,-1, +1, +2]
            k = np.array([self.N//2-1, self.N//2, self.N//2+1, self.N//2+2])
            self.active = k % self.N
        else:
            self.active = np.asarray(active_idx) % self.N

    def _pack_grid(self, syms: np.ndarray) -> np.ndarray:
        """syms shape: [n_sym, n_active] -> X[freq] shape: [n_sym, N_fft]"""
        n_sym, n_act = syms.shape
        X = np.zeros((n_sym, self.N), dtype=complex)
        X[:, self.active] = syms
        return X

    def modulate(self, qpsk_data: np.ndarray) -> tuple[np.ndarray, int]:
        """
        qpsk_data: vector 1D các ký hiệu QPSK (complex) cần phát trên 'active' subcarriers.
        Trả: x_time (complex 1D), n_sym (số OFDM symbols).
        """
        qpsk_data = np.asarray(qpsk_data)
        n_act = len(self.active)
        # pad để chia hết số subcarrier active
        rem = qpsk_data.size % n_act
        if rem != 0:
            pad = n_act - rem
            qpsk_data = np.hstack([qpsk_data, np.zeros(pad, dtype=complex)])
        n_sym = qpsk_data.size // n_act
        syms = qpsk_data.reshape(n_sym, n_act)

        X = self._pack_grid(syms)        # [n_sym, N]
        x = np.fft.ifft(X, n=self.N, axis=1)  # IFFT theo hàng
        # chèn CP
        cp = x[:, -self.cp:]
        x_cp = np.hstack([cp, x])        # [n_sym, cp+N]
        return x_cp.reshape(-1), n_sym

    def demodulate(self, y_time: np.ndarray, n_sym: int, H_f: np.ndarray | None = None) -> np.ndarray:
        """
        y_time: tín hiệu thu sau kênh (1D), n_sym: số OFDM symbols đã phát.
        H_f: đáp ứng kênh theo tần số (N_fft,) để equalize (ZF). Nếu None -> không equalize.
        Trả: vector QPSK (complex) theo thứ tự các active subcarriers.
        """
        blk_len = self.N + self.cp
        y_blk = y_time[: n_sym*blk_len].reshape(n_sym, blk_len)
        y_no_cp = y_blk[:, self.cp:]                 # remove CP -> [n_sym, N]
        Y = np.fft.fft(y_no_cp, n=self.N, axis=1)    # FFT
        if H_f is not None:
            H_eps = 1e-12
            Y = Y / np.maximum(H_f, H_eps)           # ZF equalization
        rx_syms = Y[:, self.active]                  # lấy các subcarrier active
        return rx_syms.reshape(-1)

    def channel_freq_response(self, h: np.ndarray) -> np.ndarray:
        """H(f) theo N_fft từ h FIR time-domain (để equalize)."""
        return np.fft.fft(h, n=self.N)
