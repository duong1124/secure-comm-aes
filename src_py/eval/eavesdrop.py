from src_py.aes_ops.aes_gcm import AES_GCM
from src_py.aes_ops import encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc

from src_py.eval.config_loader import load_config
from src_py.eval.image_helper import load_image, ciphertext_to_image
from src_py.eval.visualizer import plot_confidentiality_analysis


def evaluate_ecb_confidentiality(config):
    print("\n" + "=" * 70)
    print("  ECB_XOR MODE - CONFIDENTIALITY EVALUATION")
    print("=" * 70)

    # Load image
    img_data = load_image(config.image_path)

    # Encryption
    print("[*] Encrypting with ECB_XOR...")
    ciphertext = encrypt_ecb(config.crypto.key, img_data.plaintext)
    print(f"[+] Ciphertext size: {len(ciphertext)} bytes")

    # Decryption (for verification)
    print("[*] Decrypting for verification...")
    pt_dec = decrypt_ecb(config.crypto.key, ciphertext)
    correct = (pt_dec == img_data.plaintext)
    print(f"[+] Decryption {'successful' if correct else 'FAILED'}")

    # Visualization: What eavesdropper sees
    print("[*] Generating eavesdropper visualization...")
    encrypted_img = ciphertext_to_image(
        ciphertext,
        img_data.mode,
        img_data.size
    )

    plot_confidentiality_analysis(
        img_data.img,
        encrypted_img,
        "ECB_XOR",
        config.visualization
    )

    return correct


def evaluate_cbc_confidentiality(config):
    """Evaluate CBC mode confidentiality through eavesdropping simulation.

    Parameters
    ----------
    config : Config
        Configuration object containing all parameters.
    """
    print("\n" + "=" * 70)
    print("  CBC MODE - CONFIDENTIALITY EVALUATION")
    print("=" * 70)

    # Load image
    img_data = load_image(config.image_path)

    # Encryption
    print("[*] Encrypting with CBC...")
    ciphertext, iv_used = encrypt_cbc(img_data.plaintext, config.crypto.key, iv=None)
    print(f"[+] Ciphertext size: {len(ciphertext)} bytes")
    print(f"[+] IV: {iv_used.hex()[:32]}...")

    # Decryption (for verification)
    print("[*] Decrypting for verification...")
    pt_dec = decrypt_cbc(ciphertext, config.crypto.key, iv_used)
    correct = (pt_dec == img_data.plaintext)
    print(f"[+] Decryption {'successful' if correct else 'FAILED'}")

    # Visualization: What eavesdropper sees
    print("[*] Generating eavesdropper visualization...")
    encrypted_img = ciphertext_to_image(
        ciphertext,
        img_data.mode,
        img_data.size
    )

    plot_confidentiality_analysis(
        img_data.img,
        encrypted_img,
        "CBC",
        config.visualization
    )

    return correct


def evaluate_gcm_confidentiality(config):
    """Evaluate GCM mode confidentiality through eavesdropping simulation.

    Parameters
    ----------
    config : Config
        Configuration object containing all parameters.
    """
    print("\n" + "=" * 70)
    print("  GCM MODE - CONFIDENTIALITY EVALUATION")
    print("=" * 70)

    # Load image
    img_data = load_image(config.image_path)

    # Initialize GCM
    gcm = AES_GCM(
        config.crypto.key,
        config.crypto.iv_gcm,
        config.crypto.aad,
        config.crypto.tag_length
    )

    # Encryption
    print("[*] Encrypting with GCM...")
    ciphertext, tag = gcm.encrypt_gcm(img_data.plaintext)
    print(f"[+] Ciphertext size: {len(ciphertext)} bytes")
    print(f"[+] Auth tag: {tag.hex()}")

    # Decryption (for verification)
    print("[*] Decrypting for verification...")
    pt_dec = gcm.decrypt_gcm(ciphertext, tag)
    correct = (pt_dec == img_data.plaintext)
    print(f"[+] Decryption {'successful' if correct else 'FAILED'}")

    # Visualization: What eavesdropper sees
    print("[*] Generating eavesdropper visualization...")
    encrypted_img = ciphertext_to_image(
        ciphertext,
        img_data.mode,
        img_data.size
    )

    plot_confidentiality_analysis(
        img_data.img,
        encrypted_img,
        "GCM",
        config.visualization
    )

    return correct


def run_eavesdrop_evaluation():
    """Run complete eavesdropping evaluation for all encryption modes."""
    print("\n" + "=" * 70)
    print("  EAVESDROPPING ATTACK SIMULATION")
    print("  Confidentiality Evaluation of AES Encryption Modes")
    print("=" * 70)

    # Load configuration
    config = load_config()

    # Evaluate each mode
    results = {}
    results['ECB'] = evaluate_ecb_confidentiality(config)
    results['CBC'] = evaluate_cbc_confidentiality(config)
    results['GCM'] = evaluate_gcm_confidentiality(config)

    # Summary
    print("\n" + "=" * 70)
    print("  EVALUATION SUMMARY")
    print("=" * 70)
    for mode, success in results.items():
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {mode:10s}: {status}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_eavesdrop_evaluation()