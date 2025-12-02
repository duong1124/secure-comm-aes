# Absolute import using the project's package structure
from src_py.aes import AES 
import timeit

# --- 1. Data Preparation ---
KEY_128 = b"A" * 16
KEY_192 = b"B" * 24
KEY_256 = b"C" * 32
# AES block size (16 bytes)
TEST_BLOCK = b"X" * 16 
# Number of iterations for accurate timing
ITERATIONS = 10000 

def run_benchmark(key: bytes, name: str):
    """Measures Latency and Throughput for a given key size."""
    aes_instance = AES(key)
    
    # 1. Measure Encryption Time
    encryption_time = timeit.timeit(
        lambda: aes_instance.encrypt(TEST_BLOCK),
        number=ITERATIONS
    )
    
    # 2. Calculate Metrics
    total_data_bytes = len(TEST_BLOCK) * ITERATIONS
    # MiB/s calculation
    throughput_mib_s = (total_data_bytes / encryption_time) / (1024 * 1024)
    # Microseconds (us) calculation
    latency_us = (encryption_time / ITERATIONS) * 1000000
    
    print(f"--- {name} ---")
    print(f"Total time: {encryption_time:.4f} seconds")
    print(f"Throughput: {throughput_mib_s:.2f} MiB/s")
    print(f"Avg Latency: {latency_us:.4f} micro seconds")
    print("-" * 25)

if __name__ == "__main__":
    print("Starting AES Core Benchmark...")
    
    # --- Run Benchmarks ---
    run_benchmark(KEY_128, "AES-128 (10 Rounds)")
    run_benchmark(KEY_192, "AES-192 (12 Rounds)")
    run_benchmark(KEY_256, "AES-256 (14 Rounds)")