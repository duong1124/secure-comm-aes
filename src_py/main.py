import sys
import argparse
from pathlib import Path

from src_py.eval.eavesdrop import run_eavesdrop_evaluation
from src_py.eval.man_in_the_middle import run_mitm_evaluation
from src_py.eval.benchmark import run_performance_benchmark


def run_all_tests():
    try:
        # Test 1: Confidentiality
        print("\n[TEST 1/3] Confidentiality Evaluation")
        run_eavesdrop_evaluation()
        input("\nPress Enter to continue to next test...")

        # Test 2: Integrity
        print("\n[TEST 2/3] Integrity Evaluation")
        run_mitm_evaluation()
        input("\nPress Enter to continue to next test...")

        # Test 3: Performance
        print("\n[TEST 3/3] Performance Evaluation")
        run_performance_benchmark()

        print("ALL TESTS COMPLETED SUCCESSFULLY")

    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Test suite failed: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="AES Secure Communication Evaluation Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--eavesdrop',
        action='store_true',
        help='Run eavesdropping attack evaluation (confidentiality)'
    )

    parser.add_argument(
        '--mitm',
        action='store_true',
        help='Run man-in-the-middle attack evaluation (integrity)'
    )

    parser.add_argument(
        '--benchmark',
        action='store_true',
        help='Run performance benchmark'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all tests'
    )

    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )

    args = parser.parse_args()

    if not Path(args.config).exists():
        print(f"[ERROR] Configuration file not found: {args.config}")
        sys.exit(1)

    if args.all:
        run_all_tests()
    if args.eavesdrop:
        run_eavesdrop_evaluation()
    if args.mitm:
        run_mitm_evaluation()
    if args.benchmark:
        run_performance_benchmark()

if __name__ == "__main__":
    main()