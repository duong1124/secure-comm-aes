from src_py.aes_ops.aes_gcm import AES_GCM
from src_py.aes_ops import encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc

from src_py.eval.config_loader import load_config, MITMConfig
from src_py.eval.image_helper import load_image, bytes_to_image
from src_py.eval.visualizer import plot_mitm_success, plot_mitm_blocked


def tamper_ciphertext_region(ciphertext: bytes,
                             total_plain_bytes: int,
                             avoid_last_blocks: int,
                             block_size: int,
                             config: MITMConfig) -> bytes:
    """Apply a MITM-style modification to a middle region of ciphertext."""
    ct = bytearray(ciphertext)
    ct_len = len(ct)

    # avoid trailing blocks
    safe_end = ct_len - avoid_last_blocks * block_size
    if safe_end <= 0:
        safe_end = ct_len

    # choose the middle region
    plain_start = int(total_plain_bytes * config.tamper_start_ratio)
    plain_end = int(total_plain_bytes * config.tamper_end_ratio)

    start = max(0, min(plain_start, safe_end))
    end = max(start + 1, min(plain_end, safe_end))

    for i in range(start, end):
        ct[i] ^= config.xor_mask

    return bytes(ct)


class MITMAttack:
    """Helper encapsulating MITM parameters for each mode."""

    def __init__(self, config: MITMConfig):
        self.config = config

    def tamper_ecb(self, ciphertext: bytes, plaintext_len: int,
                   block_size: int) -> bytes:
        return tamper_ciphertext_region(
            ciphertext,
            total_plain_bytes=plaintext_len,
            avoid_last_blocks=self.config.avoid_last_blocks_ecb,
            block_size=block_size,
            config=self.config,
        )

    def tamper_cbc(self, ciphertext: bytes, plaintext_len: int) -> bytes:
        return tamper_ciphertext_region(
            ciphertext,
            total_plain_bytes=plaintext_len,
            avoid_last_blocks=self.config.avoid_last_blocks_cbc,
            block_size=16,
            config=self.config,
        )

    def tamper_gcm(self, ciphertext: bytes, plaintext_len: int) -> bytes:
        return tamper_ciphertext_region(
            ciphertext,
            total_plain_bytes=plaintext_len,
            avoid_last_blocks=self.config.avoid_last_blocks_gcm,
            block_size=16,
            config=self.config,
        )


def evaluate_ecb_integrity(config) -> bool:
    """Evaluate ECB_XOR integrity under MITM. Return True if attack is blocked."""
    img_data = load_image(config.image_path)
    attacker = MITMAttack(config.mitm)

    # Encrypt
    ciphertext = encrypt_ecb(config.crypto.key, img_data.plaintext)
    # MITM tampering
    tampered_ct = attacker.tamper_ecb(
        ciphertext,
        img_data.total_bytes,
        config.crypto.block_size,
    )

    # Receiver decrypts tampered data
    try:
        pt_tampered = decrypt_ecb(config.crypto.key, tampered_ct)
        tampered_img = bytes_to_image(pt_tampered, img_data.mode, img_data.size)

        # Visual: original vs tampered
        plot_mitm_success(
            img_data.img,
            tampered_img,
            "ECB_XOR",
            config.visualization,
        )
        return False  # Attack succeeded
    except Exception:
        return True


def evaluate_cbc_integrity(config) -> bool:
    """Evaluate CBC integrity under MITM. Return True if attack is blocked."""
    img_data = load_image(config.image_path)
    attacker = MITMAttack(config.mitm)

    # Encrypt
    ciphertext, iv_used = encrypt_cbc(img_data.plaintext, config.crypto.key, iv=None)
    # MITM tampering
    tampered_ct = attacker.tamper_cbc(ciphertext, img_data.total_bytes)

    # Receiver decrypts tampered data
    try:
        pt_tampered = decrypt_cbc(tampered_ct, config.crypto.key, iv_used)
        tampered_img = bytes_to_image(pt_tampered, img_data.mode, img_data.size)

        plot_mitm_success(
            img_data.img,
            tampered_img,
            "CBC",
            config.visualization,
        )
        return False  # Attack succeeded
    except Exception:
        return True


def evaluate_gcm_integrity(config) -> bool:
    """Evaluate GCM integrity under MITM. Return True if attack is blocked."""
    img_data = load_image(config.image_path)
    attacker = MITMAttack(config.mitm)

    gcm = AES_GCM(
        config.crypto.key,
        config.crypto.iv_gcm,
        config.crypto.aad,
        config.crypto.tag_length,
    )
    # Encrypt
    ciphertext, tag = gcm.encrypt_gcm(img_data.plaintext)
    # MITM tampering
    tampered_ct = attacker.tamper_gcm(ciphertext, img_data.total_bytes)

    # Receiver verifies + decrypts
    try:
        _ = gcm.decrypt_gcm(tampered_ct, tag)
        return False
    except ValueError:
        # Tag mismatch → attack blocked
        plot_mitm_blocked(
            img_data.img,
            "GCM",
            config.visualization,
        )
        return True


def run_mitm_evaluation() -> None:
    """Run MITM integrity evaluation for ECB_XOR, CBC, and GCM."""
    config = load_config()

    print("\n[MITM] Evaluating integrity of ECB_XOR, CBC, GCM ...")

    results = {
        "ECB_XOR": evaluate_ecb_integrity(config),
        "CBC": evaluate_cbc_integrity(config),
        "GCM": evaluate_gcm_integrity(config),
    }
    # Summary
    print("\n[MITM] Summary (ATTACK BLOCKED?):")
    for mode, blocked in results.items():
        status = "BLOCKED (integrity OK)" if blocked else "VULNERABLE (no integrity)"
        print(f"  {mode:7s}: {status}")
    print()


if __name__ == "__main__":
    run_mitm_evaluation()
