import os
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image

# --- 1. IMPORT CUSTOM FUNCTIONS FROM YOUR PROJECT ---
# Import your custom CBC encryption function (uses your AES core and handles padding/IV)
from src_py.aes_ops.aes_cbc import encrypt_cbc 
# Import your custom ECB encryption function (uses XOR, for demonstration only)
from src_py.aes_ops.aes_ecb import encrypt_ecb
# The AES class from src_py.aes is implicitly used within encrypt_cbc/encrypt_ecb
# from src_py.aes import AES 

# Fixed 16-byte key for both modes
KEY = b'1234567890abcdef' 
BLOCK_SIZE = 16

# --- 2. RGB Image Encryption Function (Using Custom Implementation) ---

def encrypt_rgb_image_custom(file_path: str, key: bytes, mode: str):
    """
    Encrypts an RGB image channel-by-channel using the specified custom mode (CBC or ECB_XOR).
    
    Returns: encrypted_image (Image.Image object) or None if encryption fails.
    """
    with Image.open(file_path) as img:
        original_img = img.convert("RGB")
        r, g, b = original_img.split() 
        original_size_tuple = original_img.size # (width, height)
        
    # Encrypt each channel independently using the appropriate mode function
    encrypted_r = encrypt_channel_custom(r, key, mode, original_size_tuple)
    encrypted_g = encrypt_channel_custom(g, key, mode, original_size_tuple)
    encrypted_b = encrypt_channel_custom(b, key, mode, original_size_tuple)
    
    # Merge channels if all encryptions were successful
    if encrypted_r and encrypted_g and encrypted_b:
        encrypted_image = Image.merge("RGB", (encrypted_r, encrypted_g, encrypted_b))
        return encrypted_image
    else:
        return None

def encrypt_channel_custom(channel: Image.Image, key: bytes, mode: str, original_size: tuple):
    """Encrypts a single image channel using your project's custom functions."""
    
    # 1. Get plaintext data
    plaintext = np.array(channel, dtype=np.uint8).flatten().tobytes()
    
    ciphertext = b''
    
    # 2. Encryption using the chosen mode
    if mode == 'CBC':
        # Use your encrypt_cbc function (handles padding and IV generation)
        ciphertext, _ = encrypt_cbc(plaintext, key, iv=None)
    
    elif mode == 'ECB_XOR':
        # Use your encrypt_ecb function (XOR-based implementation with padding)
        ciphertext = encrypt_ecb(key, plaintext)
    else:
        print(f"ERROR: Mode '{mode}' is not supported.")
        return None
    
    # 3. Convert Ciphertext back to image data for plotting
    total_pixels = original_size[0] * original_size[1]
    encrypted_pixels = np.frombuffer(ciphertext, dtype=np.uint8)
    
    # Cut Ciphertext back to the original pixel size (removing padding) for display purposes
    if len(encrypted_pixels) < total_pixels:
        print(f"RESHAPE ERROR: Ciphertext is too short ({len(encrypted_pixels)} bytes).")
        return None
        
    encrypted_pixels = encrypted_pixels[:total_pixels] 
    
    try:
         # Reshape back to the original (height, width) dimensions
         encrypted_channel = Image.fromarray(encrypted_pixels.reshape(original_size[::-1]), mode="L")
    except ValueError as e:
         print(f"RESHAPE ERROR: Could not reshape encrypted data. Error: {e}")
         return None
    
    return encrypted_channel

# --- 3. Plotting and Statistical Analysis Function ---

def plot_analysis(original_img: Image.Image, encrypted_img: Image.Image, mode_name: str):
    """Plots images and their pixel histograms for visual and statistical analysis."""
    
    if encrypted_img is None:
        print(f"PLOTTING SKIPPED: Encrypted image for {mode_name} is invalid.")
        return

    plt.figure(figsize=(15, 10))

    # 1. Display Original Image
    plt.subplot(2, 2, 1)
    plt.imshow(original_img)
    plt.title("1. Original Image")
    plt.axis("off")

    # 2. Display Encrypted Image
    plt.subplot(2, 2, 2)
    plt.imshow(encrypted_img)
    plt.title(f"2. Encrypted Image ({mode_name})")
    plt.axis("off")

    # 3. Plot Original Image Histogram
    plt.subplot(2, 2, 3)
    plt.hist(np.array(original_img).flatten(), bins=256, range=(0, 255), color='gray', edgecolor='black')
    plt.title("3. Original Image Histogram (Non-uniform)")
    plt.xlabel("Pixel Intensity")
    plt.ylabel("Frequency")

    # 4. Plot Encrypted Image Histogram
    plt.subplot(2, 2, 4)
    plt.hist(np.array(encrypted_img).flatten(), bins=256, range=(0, 255), color='gray', edgecolor='black')
    plt.title(f"4. Encrypted Histogram ({mode_name})")
    plt.xlabel("Pixel Intensity")
    plt.ylabel("Frequency")

    plt.tight_layout()
    plt.suptitle(f"Security Analysis: Custom AES in {mode_name} Mode", fontsize=16)
    plt.show()

# --- 4. Example Usage and Mode Comparison ---
if __name__ == "__main__":
    # Replace with the valid path to your RGB image
    FILE_PATH = r"D:\CSKTM\final_prj_wireless\final_prj_wireless\lena_img.jpg" 
    
    # Load original image only once
    try:
        with Image.open(FILE_PATH) as img:
            ORIGINAL_IMG = img.convert("RGB")
    except FileNotFoundError:
        print(f"ERROR: Image file not found at path: {FILE_PATH}")
        exit()

    # --- 4.1. Analyze CBC Mode (SECURE) ---
    print("--- Running CBC Mode Analysis (SECURE) ---")
    encrypted_cbc = encrypt_rgb_image_custom(FILE_PATH, KEY, 'CBC')
    plot_analysis(ORIGINAL_IMG, encrypted_cbc, "CBC (SECURE)")

    # --- 4.2. Analyze ECB_XOR Mode (INSECURE) ---
    # Note: Close the CBC plot window for the code to continue running
    print("--- Running ECB_XOR Mode Analysis (INSECURE) ---")
    encrypted_ecb_xor = encrypt_rgb_image_custom(FILE_PATH, KEY, 'ECB_XOR')
    plot_analysis(ORIGINAL_IMG, encrypted_ecb_xor, "ECB-XOR (INSECURE)")