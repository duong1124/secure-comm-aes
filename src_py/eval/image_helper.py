import numpy as np
from PIL import Image
from typing import Tuple


class ImageData:
    def __init__(self, img: Image.Image, plaintext: bytes, mode: str, size: Tuple[int, int]):
        self.img = img
        self.plaintext = plaintext
        self.mode = mode
        self.size = size
        self.width, self.height = size
        self.channels = 1 if mode == "L" else 3
        self.total_bytes = len(plaintext)

    def __repr__(self):
        return (f"ImageData(mode={self.mode}, size={self.size}, "
                f"bytes={self.total_bytes}, channels={self.channels})")


def load_image(img_path: str) -> ImageData:
    """
    Returns
    -------
    ImageData
        Container with image, raw bytes, and metadata.
    """
    img = Image.open(img_path)

    # Normalize to L or RGB
    if img.mode in ("L", "RGB"):
        mode_str = img.mode
    else:
        print(f"[!] Image mode {img.mode} not in (L, RGB), converting to RGB.")
        img = img.convert("RGB")
        mode_str = "RGB"

    plaintext = img.tobytes()
    size_tuple = img.size

    print(f"[+] Loaded: {len(plaintext)} bytes, mode={mode_str}, size={size_tuple}")

    return ImageData(img, plaintext, mode_str, size_tuple)


def bytes_to_image(buf: bytes, mode_str: str, size_tuple: Tuple[int, int]) -> Image.Image:
    """Reconstruct an image from raw byte buffer.
    """
    width, height = size_tuple
    channels = 1 if mode_str == "L" else 3

    total_vals = width * height * channels
    arr = np.frombuffer(buf, dtype=np.uint8)

    if len(arr) < total_vals:
        raise ValueError(f"Buffer too short: {len(arr)} < {total_vals} required")

    arr = arr[:total_vals]

    if channels == 1:
        arr = arr.reshape((height, width))
        return Image.fromarray(arr, mode="L")
    else:
        arr = arr.reshape((height, width, 3))
        return Image.fromarray(arr, mode="RGB")


def ciphertext_to_image(ciphertext: bytes, mode_str: str,
                        size_tuple: Tuple[int, int]) -> Image.Image:
    """Convert ciphertext bytes to image for visualization.
    Truncates the ciphertext to match the required image dimensions.
    """
    width, height = size_tuple
    channels = 1 if mode_str == "L" else 3

    total_values = width * height * channels
    encrypted_values = np.frombuffer(ciphertext, dtype=np.uint8)

    if len(encrypted_values) < total_values:
        raise ValueError(
            f"Ciphertext too short: {len(encrypted_values)} < {total_values} values"
        )

    encrypted_values = encrypted_values[:total_values]

    if channels == 1:
        arr = encrypted_values.reshape((height, width))
        return Image.fromarray(arr, mode="L")
    else:
        arr = encrypted_values.reshape((height, width, 3))
        return Image.fromarray(arr, mode="RGB")