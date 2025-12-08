import time
from typing import Callable, Tuple, Any, List

from src_py.aes_ops.aes_gcm import AES_GCM
from src_py.aes_ops import encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc
from src_py.eval.config_loader import load_config
from src_py.eval.image_helper import load_image


class BenchmarkResult:
    """Container for performance metrics of one encryption mode."""

    def __init__(self, mode_name: str, plaintext_size: int):
        self.mode_name = mode_name
        self.plaintext_size = plaintext_size
        self.encrypt_time: float = 0.0
        self.decrypt_time: float = 0.0
        self.correct_decrypt: bool = False

    @property
    def encrypt_throughput(self) -> float:
        """Encryption throughput in MB/s."""
        if self.encrypt_time > 0:
            return self.plaintext_size / self.encrypt_time / 1e6
        return 0.0

    @property
    def decrypt_throughput(self) -> float:
        """Decryption throughput in MB/s."""
        if self.decrypt_time > 0:
            return self.plaintext_size / self.decrypt_time / 1e6
        return 0.0


def benchmark_time(operation: Callable, *args, **kwargs) -> Tuple[float, Any]:
    """Measure execution time of a single operation.

    Returns
    -------
    Tuple[float, Any]
        (elapsed_time_in_seconds, operation_result)
    """
    start_time = time.time()
    result = operation(*args, **kwargs)
    elapsed_time = time.time() - start_time
    return elapsed_time, result


def benchmark_ecb_performance(config) -> BenchmarkResult:
    """Benchmark ECB_XOR mode performance."""
    img_data = load_image(config.image_path)
    result = BenchmarkResult("ECB_XOR", img_data.total_bytes)

    # Encryption
    result.encrypt_time, ciphertext = benchmark_time(
        encrypt_ecb,
        config.crypto.key,
        img_data.plaintext,
    )

    # Decryption
    result.decrypt_time, pt_dec = benchmark_time(
        decrypt_ecb,
        config.crypto.key,
        ciphertext,
    )

    # Correctness
    result.correct_decrypt = (pt_dec == img_data.plaintext)
    return result


def benchmark_cbc_performance(config) -> BenchmarkResult:
    """Benchmark CBC mode performance."""
    img_data = load_image(config.image_path)
    result = BenchmarkResult("CBC", img_data.total_bytes)

    # Encryption (trả về (ciphertext, iv_used))
    def encrypt_wrapper():
        return encrypt_cbc(img_data.plaintext, config.crypto.key, iv=None)

    result.encrypt_time, (ciphertext, iv_used) = benchmark_time(encrypt_wrapper)

    # Decryption
    result.decrypt_time, pt_dec = benchmark_time(
        decrypt_cbc,
        ciphertext,
        config.crypto.key,
        iv_used,
    )

    # Correctness
    result.correct_decrypt = (pt_dec == img_data.plaintext)
    return result


def benchmark_gcm_performance(config) -> BenchmarkResult:
    """Benchmark GCM mode performance."""
    img_data = load_image(config.image_path)
    result = BenchmarkResult("GCM", img_data.total_bytes)

    gcm = AES_GCM(
        config.crypto.key,
        config.crypto.iv_gcm,
        config.crypto.aad,
        config.crypto.tag_length,
    )

    # Encryption
    result.encrypt_time, (ciphertext, tag) = benchmark_time(
        gcm.encrypt_gcm,
        img_data.plaintext,
    )

    # Decryption
    result.decrypt_time, pt_dec = benchmark_time(
        gcm.decrypt_gcm,
        ciphertext,
        tag,
    )

    # Correctness
    result.correct_decrypt = (pt_dec == img_data.plaintext)
    return result


def print_performance_summary(results: List[BenchmarkResult]) -> None:
    """Print a single consolidated performance table for all modes."""
    if not results:
        print("No eval results to display.")
        return

    print("\n" + "=" * 90)
    print("AES ENCRYPTION PERFORMANCE BENCHMARK")
    print("=" * 90)

    header = (
        f"{'Mode':<10}"
        f"{'Size (bytes)':>15}"
        f"{'Enc time (s)':>15}"
        f"{'Enc MB/s':>12}"
        f"{'Dec time (s)':>15}"
        f"{'Dec MB/s':>12}"
        f"{'OK':>6}"
    )
    print(header)
    print("-" * len(header))

    for r in results:
        row = (
            f"{r.mode_name:<10}"
            f"{r.plaintext_size:>15,d}"
            f"{r.encrypt_time:>15.6f}"
            f"{r.encrypt_throughput:>12.2f}"
            f"{r.decrypt_time:>15.6f}"
            f"{r.decrypt_throughput:>12.2f}"
            f"{('YES' if r.correct_decrypt else 'NO'):>6}"
        )
        print(row)

    print("=" * 90 + "\n")


def run_performance_benchmark() -> None:
    """Run complete performance eval for all encryption modes."""
    config = load_config()

    results: List[BenchmarkResult] = [
        benchmark_ecb_performance(config),
        benchmark_cbc_performance(config),
        benchmark_gcm_performance(config),
    ]

    print_performance_summary(results)


if __name__ == "__main__":
    run_performance_benchmark()
