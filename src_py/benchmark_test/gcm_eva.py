import os
import time
from PIL import Image
import binascii

# --- NECESSARY IMPORTS BASED ON YOUR PROJECT STRUCTURE ---
# 1. AES_GCM Class (Your GCM implementation)
from src_py.aes_ops.aes_gcm import AES_GCM 
# 2. AES Class (Your core algorithm)
from src_py.aes import AES 

# --- YOUR TEST PARAMETERS ---
# You need to change this path to a valid image file on your machine
FILE_PATH = r"D:\CSKTM\final_prj_wireless\final_prj_wireless\non_Dicom_image.jpg"
KEY = b'sixteen bit key.' # 16 byte key (Ensure it is 16, 24, or 32 bytes)
IV = b'12byte nonce'      # 12 byte Nonce (Standard GCM)
A = b'GCM_auth_data'     # Additional Authenticated Data (AAD)
TAG_LEN = 16              # Tag length (16 bytes)

# --- 2. MAIN FUNCTION FOR RUNNING TESTS ---

def run_gcm_evaluation(img_path: str):
    
    # 2.1. Prepare image data
    try:
        # Ensure the image can be opened and converted to RGB mode (3 channels)
        img_original = Image.open(img_path).convert("RGB") 
        plaintext = img_original.tobytes()
        mode_str = img_original.mode
        size_tuple = img_original.size
        print(f"Image data size: {len(plaintext)} bytes")
    except FileNotFoundError:
        print(f"ERROR: Image file not found at path: {img_path}")
        return
    except Exception as e:
        print(f"ERROR when processing image: {e}")
        return

    # 2.2. Initialize GCM (Using AES_GCM from src_py.aes_ops)
    gcm = AES_GCM(KEY, IV, A, TAG_LEN)
    
    # --- PART 1: FUNCTIONALITY AND PERFORMANCE TEST ---
    print("\n--- PART 1: FUNCTIONALITY AND PERFORMANCE TEST ---")
    
    # Encryption
    start_time_enc = time.time()
    ciphertext, tag = gcm.encrypt_gcm(plaintext)
    time_encryption = time.time() - start_time_enc

    # Decryption
    start_time_dec = time.time()
    pt_decrypted = gcm.decrypt_gcm(ciphertext, tag)
    time_decryption = time.time() - start_time_dec
    
    # Verify successful decryption
    is_success = (pt_decrypted == plaintext)
    
    print(f"-> Encryption/Decryption successful: {is_success}")
    print(f"-> Encryption time: {time_encryption:.4f} seconds")
    print(f"-> Decryption time: {time_decryption:.4f} seconds")
    
    # --- PART 2: INTEGRITY TEST (ANTI-TAMPERING) ---
    print("\n--- PART 2: INTEGRITY TEST (Tampering) ---")
    
    # 2.3. Scenario 1: Tamper with Ciphertext (C)
    tampered_ciphertext = bytearray(ciphertext)
    # Flip 1 bit in the first byte
    tampered_ciphertext[0] = tampered_ciphertext[0] ^ 0x01 
    tampered_ciphertext = bytes(tampered_ciphertext)
    
    # Attempt decryption with tampered C (Must raise error)
    result_tamper_c = 'FAIL'
    try:
        gcm.decrypt_gcm(tampered_ciphertext, tag)
    except ValueError:
        result_tamper_c = 'PASS' # Detection successful
    
    print("Scenario 1: Tampering with Ciphertext (C)")
    print(f"-> Tamper detection: {result_tamper_c}")
    
    # 2.4. Scenario 2: Tamper with Associated Data (AAD)
    # Initialize a new GCM context with altered AAD
    gcm_tampered_a = AES_GCM(KEY, IV, b'TAMPERED_AAD', TAG_LEN)
    result_tamper_a = 'FAIL'
    try:
        gcm_tampered_a.decrypt_gcm(ciphertext, tag)
    except ValueError:
        result_tamper_a = 'PASS'
    
    print("Scenario 2: Tampering with Associated Data (A)")
    print(f"-> Tamper detection: {result_tamper_a}")

    # --- PART 3: VISUAL ANALYSIS ---
    if is_success:
        try:
            # Save the encrypted image (Ciphertext)
            cipher_image = Image.frombytes(mode_str, size_tuple, ciphertext)
            cipher_image.save('GCM_cipher_image_visual.jpg')
            print("\n-> Saved 'GCM_cipher_image_visual.jpg' to check for diffusion.")
            
            # Save the decrypted image (Decrypted Plaintext)
            img_copy = Image.frombytes(mode_str, size_tuple, pt_decrypted)
            img_copy.save('GCM_image_copy_visual.jpg')
            print("-> Saved 'GCM_image_copy_visual.jpg' to check data recovery.")
            
        except ValueError:
            print("\nERROR: Cannot create image from bytes (possibly padding/size error).")


if __name__ == "__main__":
    run_gcm_evaluation(FILE_PATH)