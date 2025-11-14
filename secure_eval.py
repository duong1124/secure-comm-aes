from __future__ import annotations
import numpy as np
from ofdm import OFDM, pskmod, pskdemod, add_awgn, random_fir_channel
from utils import text_to_bytes, bytes_to_text, bytes_to_bits, bits_to_bytes, calculate_ber
from aes_ops import encrypt_cbc, decrypt_cbc

def bits_to_syms_qpsk(bits):
    if bits.size % 2 != 0: bits = np.hstack([bits, 0])
    idx = bits.reshape(-1,2)[:,0]*2 + bits.reshape(-1,2)[:,1]
    return pskmod(idx, 4)

def syms_to_bits_qpsk(syms):
    idx = pskdemod(syms, 4)
    b0 = (idx // 2) & 1; b1 = idx % 2
    return np.column_stack([b0,b1]).reshape(-1).astype(int)

def simulate_bob_eve(message="wiretap test", snr_bob=12.0, snr_eve=6.0,
                     jnr_db=None, # nếu đặt số -> thêm jammer công suất JNR (dB) tại Eve
                     seed=7):
    rng = np.random.default_rng(seed)
    key = b"SecretKey1234567"
    ofdm = OFDM(N_fft=16, cp_len=2)

    # Encrypt
    pt = text_to_bytes(message)
    ct, iv = encrypt_cbc(pt, key)
    bits = np.array(bytes_to_bits(ct), dtype=int)
    tx_syms = bits_to_syms_qpsk(bits)
    x, n_sym = ofdm.modulate(tx_syms)

    # Bob channel
    h_b = random_fir_channel(3, rng=rng)
    yb = np.convolve(x, h_b, mode='full')
    yb = add_awgn(yb, snr_bob, rng=rng)
    XHb = ofdm.channel_freq_response(h_b)
    rb_syms = ofdm.demodulate(yb, n_sym, H_f=XHb)
    rb_bits = syms_to_bits_qpsk(rb_syms)[:len(bits)]
    ber_b = calculate_ber(bits, rb_bits)
    ok_b = False
    try:
        rxct_b = bits_to_bytes(rb_bits)[:len(ct)]
        ok_b = (bytes_to_text(decrypt_cbc(rxct_b, key, iv)) == message)
    except Exception:
        ok_b = False

    # Eve channel (nghe lén)
    h_e = random_fir_channel(3, rng=rng)
    ye = np.convolve(x, h_e, mode='full')

    # Optional: jammer tại Eve (tấn công chủ động)
    if jnr_db is not None:
        p_sig = np.mean(np.abs(ye)**2)
        jnr_lin = 10**(jnr_db/10.0)
        p_jam = p_sig / jnr_lin
        jam = np.sqrt(p_jam/2)*(rng.standard_normal(ye.shape)+1j*rng.standard_normal(ye.shape))
        ye = ye + jam

    ye = add_awgn(ye, snr_eve, rng=rng)
    XHe = ofdm.channel_freq_response(h_e)
    re_syms = ofdm.demodulate(ye, n_sym, H_f=XHe)
    re_bits = syms_to_bits_qpsk(re_syms)[:len(bits)]
    ber_e = calculate_ber(bits, re_bits)
    ok_e = False
    try:
        rxct_e = bits_to_bytes(re_bits)[:len(ct)]
        ok_e = (bytes_to_text(decrypt_cbc(rxct_e, key, iv)) == message)
    except Exception:
        ok_e = False

    print(f"[Bob] SNR={snr_bob:.1f} dB -> BER={ber_b:.3e}, Decrypt OK={ok_b}")
    print(f"[Eve] SNR={snr_eve:.1f} dB -> BER={ber_e:.3e}, Decrypt OK={ok_e}"
          + (f", JNR={jnr_db:.1f} dB (jammer)" if jnr_db is not None else ""))
    return dict(BER_Bob=ber_b, BER_Eve=ber_e, OK_Bob=ok_b, OK_Eve=ok_e)

if __name__ == "__main__":
    simulate_bob_eve(snr_bob=14, snr_eve=6, jnr_db=None)
