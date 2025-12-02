import os
import time
import sys
import numpy as np
import matplotlib.pyplot as plt

# --- 1. IMPORT CUSTOM FUNCTIONS FROM YOUR PROJECT ---
from src_py.aes_ops.aes_cbc import encrypt_cbc, decrypt_cbc
from src_py.aes_ops.aes_gcm import AES_GCM 

# --- 2. FIXED PARAMETERS ---
KEY = b'1234567890abcdef'      
IV_CBC = os.urandom(16)        
IV_GCM = os.urandom(12)        
AAD_TEST = b'AUTHENTICATED_DATA' 
TAG_LEN = 16                   

def run_file_evaluation(file_path: str):
    
    try:
        with open(file_path, 'rb') as f:
            DATA = f.read() 
        
        DATA_SIZE_BYTES = len(DATA)
        if DATA_SIZE_BYTES == 0:
            print("ERROR: File is empty.")
            return
            
        DATA_SIZE_MB = DATA_SIZE_BYTES / (1024 * 1024)
        
    except FileNotFoundError:
        print(f"ERROR: File not found at {file_path}. Please check the path.")
        return

    print(f"\n--- COMPREHENSIVE FILE BENCHMARK ---")
    print(f"Data Size: {DATA_SIZE_BYTES} bytes ({DATA_SIZE_MB:.4f} MB)")
    
    # --- MODE 1: AES-CBC ---
    print("\n--- MODE: AES-CBC (Cipher Block Chaining) ---")
    
    start_time_enc_cbc = time.time()
    CT_CBC, IV_OUT = encrypt_cbc(DATA, KEY, iv=IV_CBC)
    time_encryption_cbc = time.time() - start_time_enc_cbc

    start_time_dec_cbc = time.time()
    PT_DEC_CBC = decrypt_cbc(CT_CBC, KEY, IV_CBC)
    time_decryption_cbc = time.time() - start_time_dec_cbc
    
    is_success_cbc = (PT_DEC_CBC == DATA)
    total_time_cbc = time_encryption_cbc + time_decryption_cbc
    throughput_cbc = DATA_SIZE_MB / total_time_cbc
    
    print(f"-> Enc/Dec Success: {is_success_cbc}")
    print(f"-> Encryption Time: {time_encryption_cbc:.4f} s")
    print(f"-> Decryption Time: {time_decryption_cbc:.4f} s")
    print(f"-> Total Throughput: {throughput_cbc:.2f} MiB/s")
    
    # --- MODE 2: AES-GCM ---
    print("\n--- MODE: AES-GCM (Galois/Counter Mode) ---")

    gcm = AES_GCM(KEY, IV_GCM, AAD_TEST, TAG_LEN)
    
    start_time_enc_gcm = time.time()
    CT_GCM, TAG_OUT = gcm.encrypt_gcm(DATA)
    time_encryption_gcm = time.time() - start_time_enc_gcm

    start_time_dec_gcm = time.time()
    PT_DEC_GCM = gcm.decrypt_gcm(CT_GCM, TAG_OUT)
    time_decryption_gcm = time.time() - start_time_dec_gcm
    
    is_success_gcm = (PT_DEC_GCM == DATA)
    total_time_gcm = time_encryption_gcm + time_decryption_gcm
    throughput_gcm = DATA_SIZE_MB / total_time_gcm
    
    print(f"-> Enc/Dec Success: {is_success_gcm}")
    print(f"-> Encryption Time: {time_encryption_gcm:.4f} s")
    print(f"-> Decryption Time: {time_decryption_gcm:.4f} s")
    print(f"-> Total Throughput: {throughput_gcm:.2f} MiB/s")

    # --- INTEGRITY TEST (GCM's Core Value) ---
    print("\n--- INTEGRITY TEST: GCM ANTI-TAMPERING ---")

    # Scenario: Tamper with Ciphertext
    tampered_ciphertext = bytearray(CT_GCM)
    tampered_ciphertext[0] = tampered_ciphertext[0] ^ 0x01 
    tampered_ciphertext = bytes(tampered_ciphertext)
    
    result_tamper_c = 'FAIL'
    try:
        gcm.decrypt_gcm(tampered_ciphertext, TAG_OUT)
    except ValueError:
        result_tamper_c = 'PASS'
    
    print(f"-> Tamper Ciphertext: {result_tamper_c}")
    
    # Scenario: Tamper with AAD
    gcm_tampered_a = AES_GCM(KEY, IV_GCM, b'TAMPERED_AAD', TAG_LEN)
    result_tamper_a = 'FAIL'
    try:
        gcm_tampered_a.decrypt_gcm(CT_GCM, TAG_OUT)
    except ValueError:
        result_tamper_a = 'PASS'
    
    print(f"-> Tamper AAD: {result_tamper_a}")

# --- 4. MAIN EXECUTION ---

if __name__ == "__main__":
    
    # ⚠️ CHANGE THIS PATH ⚠️
    CUSTOM_FILE_PATH = r"D:\CSKTM\final_prj_wireless\final_prj_wireless\non_Dicom_image.jpg"
    
    run_file_evaluation(CUSTOM_FILE_PATH)