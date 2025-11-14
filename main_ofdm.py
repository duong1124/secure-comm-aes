# main_ofdm.py
from __future__ import annotations
import numpy as np
from aes_ops import encrypt_cbc, decrypt_cbc
from utils import text_to_bytes, bytes_to_text, bytes_to_bits, bits_to_bytes, calculate_ber
from ofdm import OFDM, pskmod, pskdemod, add_awgn, random_fir_channel

def bits_to_syms_qpsk(bits: np.ndarray) -> np.ndarray:
    """Nhóm 2-bit -> 0..3 -> QPSK như MATLAB pskmod."""
    if bits.size % 2 != 0:
        bits = np.hstack([bits, 0])
    dibits = bits.reshape(-1, 2)
    idx = dibits[:,0]*2 + dibits[:,1]   # 00->0, 01->1, 10->2, 11->3
    return pskmod(idx, 4)

def syms_to_bits_qpsk(syms: np.ndarray) -> np.ndarray:
    idx = pskdemod(syms, 4)             # 0..3
    b0 = (idx // 2) & 1
    b1 = idx % 2
    return np.column_stack([b0, b1]).reshape(-1).astype(int)

def run_once(message="Secure OFDM + AES-CBC demo", snr_db=12.0, seed=2025):
    rng = np.random.default_rng(seed)

    # --- AES encrypt ---
    key = b"SecretKey1234567"
    pt = text_to_bytes(message)
    ct, iv = encrypt_cbc(pt, key)
    bits = np.array(bytes_to_bits(ct), dtype=int)

    # --- Map bits -> QPSK symbols ---
    tx_syms = bits_to_syms_qpsk(bits)

    # --- OFDM modulate ---
    ofdm = OFDM(N_fft=16, cp_len=2)             # 4 active subcarriers mặc định
    x_time, n_sym = ofdm.modulate(tx_syms)

    # --- Channel (FIR + AWGN) ---
    h_bob = random_fir_channel(L=2, rng=rng)    # kênh Bob
    y_bob = np.convolve(x_time, h_bob, mode='full')
    y_bob = add_awgn(y_bob, snr_db, rng=rng)

    # --- OFDM demod + equalize ---
    Hf_bob = ofdm.channel_freq_response(h_bob)
    rx_syms_bob = ofdm.demodulate(y_bob, n_sym, H_f=Hf_bob)

    # --- Demap QPSK -> bits ---
    rx_bits_bob = syms_to_bits_qpsk(rx_syms_bob)[:len(bits)]  # cắt đúng độ dài

    # --- AES decrypt ---
    rx_ct_bob = bytes(rx_bits_bob.tolist())
    rx_ct_bob = bits_to_bytes(rx_bits_bob)[:len(ct)]
    try:
        dec = decrypt_cbc(rx_ct_bob, key, iv)
        msg_out = bytes_to_text(dec)
        ok = (msg_out == message)
    except Exception:
        msg_out = "[DECRYPTION FAILED]"
        ok = False

    ber = calculate_ber(bits, rx_bits_bob)
    print(f"SNR={snr_db:.1f} dB | BER_Bob={ber:.3e} | Decryption OK: {ok}")
    return ber, ok, msg_out

if __name__ == "__main__":
    run_once()
