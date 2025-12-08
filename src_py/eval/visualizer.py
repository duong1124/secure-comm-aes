import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
from typing import Optional

from src_py.eval.config_loader import VisualizationConfig


def plot_confidentiality_analysis(original_img: Image.Image,
                                  encrypted_img: Optional[Image.Image],
                                  mode_name: str,
                                  config: VisualizationConfig):
    """Plot images and histograms for confidentiality analysis.
    """
    if encrypted_img is None:
        print(f"[!] Plotting skipped: Encrypted image for {mode_name} is invalid.")
        return

    fig = plt.figure(figsize=config.figure_size_comparison)

    # 1. Original Image
    plt.subplot(2, 2, 1)
    plt.imshow(original_img, cmap='gray' if original_img.mode == 'L' else None)
    plt.title("1. Original Image", fontsize=12, fontweight='bold')
    plt.axis("off")

    # 2. Encrypted Image
    plt.subplot(2, 2, 2)
    plt.imshow(encrypted_img, cmap='gray' if encrypted_img.mode == 'L' else None)
    plt.title(f"2. Encrypted Image ({mode_name})", fontsize=12, fontweight='bold')
    plt.axis("off")

    # 3. Original Histogram
    plt.subplot(2, 2, 3)
    plt.hist(
        np.array(original_img).flatten(),
        bins=config.histogram_bins,
        range=config.histogram_range,
        color='steelblue',
        edgecolor='black',
        alpha=0.7
    )
    plt.title("3. Original Histogram (Non-uniform)", fontsize=11)
    plt.xlabel("Pixel Intensity", fontsize=10)
    plt.ylabel("Frequency", fontsize=10)
    plt.grid(axis='y', alpha=0.3)

    # 4. Encrypted Histogram
    plt.subplot(2, 2, 4)
    plt.hist(
        np.array(encrypted_img).flatten(),
        bins=config.histogram_bins,
        range=config.histogram_range,
        color='coral',
        edgecolor='black',
        alpha=0.7
    )
    plt.title(f"4. Encrypted Histogram ({mode_name})", fontsize=11)
    plt.xlabel("Pixel Intensity", fontsize=10)
    plt.ylabel("Frequency", fontsize=10)
    plt.grid(axis='y', alpha=0.3)

    plt.suptitle(
        f"Confidentiality Analysis: {mode_name} Mode",
        fontsize=16,
        fontweight='bold'
    )
    plt.tight_layout()
    plt.show()


def plot_mitm_success(original_img: Image.Image,
                      tampered_img: Image.Image,
                      mode_name: str,
                      config: VisualizationConfig):
    """Plot comparison when MITM attack succeeds (no integrity protection).
    """
    fig = plt.figure(figsize=config.figure_size_comparison)

    # 1. Original Image
    plt.subplot(2, 2, 1)
    plt.imshow(original_img, cmap='gray' if original_img.mode == 'L' else None)
    plt.title("1. Original Image", fontsize=12, fontweight='bold')
    plt.axis("off")

    # 2. Tampered Image
    plt.subplot(2, 2, 2)
    plt.imshow(tampered_img, cmap='gray' if tampered_img.mode == 'L' else None)
    plt.title(f"2. After MITM Attack ({mode_name})", fontsize=12, fontweight='bold')
    plt.axis("off")

    # 3. Original Histogram
    plt.subplot(2, 2, 3)
    plt.hist(
        np.array(original_img).flatten(),
        bins=config.histogram_bins,
        range=config.histogram_range,
        color='green',
        edgecolor='black',
        alpha=0.7
    )
    plt.title("3. Original Histogram", fontsize=11)
    plt.xlabel("Pixel Intensity", fontsize=10)
    plt.ylabel("Frequency", fontsize=10)
    plt.grid(axis='y', alpha=0.3)

    # 4. Tampered Histogram
    plt.subplot(2, 2, 4)
    plt.hist(
        np.array(tampered_img).flatten(),
        bins=config.histogram_bins,
        range=config.histogram_range,
        color='red',
        edgecolor='black',
        alpha=0.7
    )
    plt.title(f"4. After MITM ({mode_name})", fontsize=11)
    plt.xlabel("Pixel Intensity", fontsize=10)
    plt.ylabel("Frequency", fontsize=10)
    plt.grid(axis='y', alpha=0.3)

    plt.suptitle(
        f"⚠️ MITM Attack SUCCESS on {mode_name} (No Integrity Protection)",
        fontsize=16,
        fontweight='bold',
        color='darkred'
    )
    plt.tight_layout()
    plt.show()


def plot_mitm_blocked(original_img: Image.Image,
                      mode_name: str,
                      config: VisualizationConfig):
    """Plot result when MITM attack is blocked by integrity check.
    """
    fig = plt.figure(figsize=config.figure_size_blocked)

    # 1. Original Image
    plt.subplot(1, 2, 1)
    plt.imshow(original_img, cmap='gray' if original_img.mode == 'L' else None)
    plt.title("Original Image", fontsize=12, fontweight='bold')
    plt.axis("off")

    # 2. Blocked Message
    plt.subplot(1, 2, 2)
    plt.axis("off")
    message = (
        "MITM ATTACK BLOCKED\n\n"
        f"{mode_name} detected ciphertext tampering.\n\n"
    )
    plt.text(
        0.5, 0.5,
        message,
        ha="center",
        va="center",
        fontsize=14,
        bbox=dict(boxstyle='round,pad=1', facecolor='lightgreen', alpha=0.8),
        family='monospace'
    )

    plt.suptitle(
        f"✓ MITM Attack BLOCKED by {mode_name} Integrity Check",
        fontsize=16,
        fontweight='bold',
        color='darkgreen'
    )
    plt.tight_layout()
    plt.show()