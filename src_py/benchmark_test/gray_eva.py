import os
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image

# --- 1. IMPORT CÁC HÀM TỪ DỰ ÁN CỦA BẠN ---
# Import các hàm mã hóa/giải mã CBC và ECB (XOR) của bạn
from src_py.aes_ops.aes_cbc import encrypt_cbc 
from src_py.aes_ops.aes_ecb import encrypt_ecb
# Import helper để dùng pkcs7_unpad nếu cần (mặc dù các hàm trên đã tự xử lý)
from src_py.aes_ops.helper import pkcs7_unpad 

# Khóa 16 byte (AES-128)
KEY = b'1234567890abcdef' 
BLOCK_SIZE = 16

# --- 2. Hàm Mã hóa Ảnh Xám (Sử dụng Triển khai Dự án) ---

def encrypt_gray_image_custom(file_path: str, key: bytes, mode: str):
    """
    Encrypts a grayscale image using the specified custom mode (CBC or ECB_XOR).
    
    Returns: original_img, encrypted_img (or None if reshape fails)
    """
    # Load the image and convert to grayscale
    with Image.open(file_path) as img:
        original_img = img.convert("L")  
    
    # Get pixel data, flatten, and convert to bytes
    plaintext = np.array(original_img, dtype=np.uint8).flatten().tobytes()
    original_pixels_count = len(plaintext)
    
    ciphertext = b''
    
    # --- Mã hóa bằng hàm của dự án ---
    if mode == 'CBC':
        # Sử dụng hàm encrypt_cbc (sẽ tự xử lý padding và IV)
        # encrypt_cbc trả về (ciphertext, iv)
        ciphertext, _ = encrypt_cbc(plaintext, key, iv=None)
    
    elif mode == 'ECB_XOR':
        # Sử dụng hàm encrypt_ecb (triển khai XOR yếu của bạn)
        # encrypt_ecb xử lý padding và XOR với key
        ciphertext = encrypt_ecb(key, plaintext)
    else:
        print(f"LỖI: Chế độ '{mode}' không được hỗ trợ.")
        return original_img, None
    
    # --- Chuyển đổi lại thành hình ảnh ---
    encrypted_pixels = np.frombuffer(ciphertext, dtype=np.uint8)
    
    # Cắt Ciphertext về kích thước pixel ban đầu (bỏ qua padding) để hiển thị
    if len(encrypted_pixels) < original_pixels_count:
        print(f"LỖI RESHAPE: Ciphertext quá ngắn ({len(encrypted_pixels)} bytes).")
        return original_img, None
        
    encrypted_pixels = encrypted_pixels[:original_pixels_count] 
    
    try:
         # Reshape về kích thước (height, width) của ảnh gốc
         encrypted_image = Image.fromarray(encrypted_pixels.reshape(original_img.size), mode="L")
    except ValueError as e:
         print(f"LỖI RESHAPE: Không thể reshape dữ liệu mã hóa. Lỗi: {e}")
         return original_img, None
    
    return original_img, encrypted_image


# --- 3. Hàm Plotting và Phân tích Thống kê (Giữ nguyên) ---

def plot_analysis(original_img: Image.Image, encrypted_img: Image.Image, mode_name: str):
    """Plots images and their pixel histograms for visual and statistical analysis."""
    
    if encrypted_img is None:
        print(f"KHÔNG THỂ PLOT: Ảnh mã hóa trong chế độ {mode_name} không hợp lệ.")
        return

    plt.figure(figsize=(14, 10))
    plt.suptitle(f"Security Analysis: Custom AES in {mode_name} Mode", fontsize=16)

    # 1. Display Original Image
    plt.subplot(2, 2, 1)
    plt.imshow(original_img, cmap="gray")
    plt.title("1. Original Image")
    plt.axis("off")

    # 2. Display Encrypted Image
    plt.subplot(2, 2, 2)
    plt.imshow(encrypted_img, cmap="gray")
    plt.title(f"2. Encrypted Image ({mode_name})")
    plt.axis("off")

    # 3. Plot Original Image Histogram
    plt.subplot(2, 2, 3)
    plt.hist(np.array(original_img).flatten(), bins=256, range=(0, 255), color='gray', edgecolor='black')
    plt.title("3. Original Histogram (Non-uniform)")
    plt.xlabel("Pixel Intensity")
    plt.ylabel("Frequency")

    # 4. Plot Encrypted Image Histogram
    plt.subplot(2, 2, 4)
    plt.hist(np.array(encrypted_img).flatten(), bins=256, range=(0, 255), color='gray', edgecolor='black')
    plt.title(f"4. Encrypted Histogram ({mode_name})")
    plt.xlabel("Pixel Intensity")
    plt.ylabel("Frequency")

    plt.tight_layout(rect=[0, 0.03, 1, 0.95]) # Adjust layout for suptitle
    plt.show()

# --- 4. Ví dụ Sử dụng và So sánh ---

if __name__ == "__main__":
    # --- CÀI ĐẶT THAM SỐ CỦA BẠN ---
    FILE_PATH = r"D:\CSKTM\final_prj_wireless\final_prj_wireless\non_Dicom_image.jpg"
    
    # --- A. Phân tích Chế độ KHÔNG AN TOÀN (ECB_XOR) ---
    print("--- Running ECB_XOR Mode Analysis (INSECURE) ---")
    original_ecb, encrypted_ecb = encrypt_gray_image_custom(FILE_PATH, KEY, 'ECB_XOR')
    plot_analysis(original_ecb, encrypted_ecb, "ECB-XOR (INSECURE)")

    # --- B. Phân tích Chế độ AN TOÀN (CBC) ---
    # Chú ý: Cần đóng cửa sổ plot ECB để code tiếp tục chạy
    print("\n--- Running CBC Mode Analysis (SECURE) ---")
    original_cbc, encrypted_cbc = encrypt_gray_image_custom(FILE_PATH, KEY, 'CBC')
    plot_analysis(original_cbc, encrypted_cbc, "CBC (SECURE)")