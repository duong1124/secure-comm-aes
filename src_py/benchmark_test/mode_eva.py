import timeit
import os
import sys

# --- 1. IMPORT CUSTOM FUNCTIONS FROM YOUR PROJECT ---
from src_py.aes import AES
from src_py.aes_ops.aes_ecb import encrypt_ecb
from src_py.aes_ops.aes_cbc import encrypt_cbc
from src_py.aes_ops.aes_gcm import AES_GCM
from src_py.aes_ops.helper import pkcs7_pad 

# --- 2. FIXED PARAMETERS ---
KEY_128 = b"A" * 16 # 16-byte key for AES-128
IV_16 = os.urandom(16)      # 16-byte IV for CBC
IV_12 = os.urandom(12)      # 12-byte IV/Nonce for GCM
AAD_0 = b""                 # Empty Additional Authenticated Data

# --- 3. MAIN BENCHMARK EXECUTION FUNCTION ---

def benchmark_mode(mode_name: str, encrypt_func, data: bytes, data_size_mb: float):
    """
    Measures the time taken to encrypt the data once and calculates the throughput (MiB/s).
    """
    print(f"--- {mode_name} ---")
    
    # Measure time
    start_time = timeit.default_timer()
    encrypt_func(data)
    end_time = timeit.default_timer()
    
    total_time = end_time - start_time
    
    # Calculate Throughput
    throughput_mib_s = data_size_mb / total_time
    
    # Display results
    print(f"Total time: {total_time:.4f} seconds")
    print(f"Throughput: {throughput_mib_s:.4f} MiB/s")
    print("-" * 25)

# --- 4. WRAPPER FUNCTIONS TO CALL YOUR MODES ---

def encrypt_test_ecb(data):
    # ECB (Weak XOR implementation) - Requires only key and data
    encrypt_ecb(KEY_128, data) 

def encrypt_test_cbc(data):
    # CBC - Requires IV, self-generates if None is passed, but we pass a fixed IV here
    encrypt_cbc(data, KEY_128, iv=IV_16) 
    
def encrypt_test_gcm(data):
    # GCM - Requires Context initialization and fixed IV/AAD
    gcm_context = AES_GCM(KEY_128, IV_12, AAD_0)
    gcm_context.encrypt_gcm(data)

# --- 5. MAIN EXECUTION FLOW ---

if __name__ == "__main__":
    
    # 5.1. File Path Setup
    # You MUST change this path to an actual image/file on your machine
    CUSTOM_FILE_PATH = r"D:\CSKTM\final_prj_wireless\final_prj_wireless\non_Dicom_image.jpg"
    
    # 5.2. Read file and calculate size metrics
    try:
        with open(CUSTOM_FILE_PATH, 'rb') as f:
            TEST_DATA = f.read() 
        
        DATA_SIZE_BYTES = len(TEST_DATA)
        # Calculate size in MB and KB
        DATA_SIZE_MB = DATA_SIZE_BYTES / (1024 * 1024)
        DATA_SIZE_KB = DATA_SIZE_BYTES / 1024 
        
        if DATA_SIZE_BYTES == 0:
            print("ERROR: File is empty. Please select a file that contains data.")
            sys.exit(1)
            
    except FileNotFoundError:
        print(f"ERROR: File not found at {CUSTOM_FILE_PATH}. Please check the path.")
        sys.exit(1)
        
    print(f"Starting File Benchmark. Data size: {DATA_SIZE_KB:.2f} KB ({DATA_SIZE_MB:.4f} MB)")
    
    # 5.3. Run Benchmark for each mode
    
    # 1. ECB (Baseline Speed, INSECURE)
    benchmark_mode("AES-ECB (Insecure)", encrypt_test_ecb, TEST_DATA, DATA_SIZE_MB)
    
    # 2. CBC (Secure, Balanced Speed)
    benchmark_mode("AES-CBC", encrypt_test_cbc, TEST_DATA, DATA_SIZE_MB)
    
    # 3. GCM (Secure, Authenticated - Highest Cost)
    benchmark_mode("AES-GCM (Auth)", encrypt_test_gcm, TEST_DATA, DATA_SIZE_MB)