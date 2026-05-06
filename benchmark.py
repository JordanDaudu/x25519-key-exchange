"""
Benchmark script for the X25519 key exchange project.

This script measures the practical performance of our educational X25519
implementation.

The assignment asks us to discuss practical properties such as:
- key generation time
- shared secret derivation time
- key sizes

This benchmark provides concrete numbers that can later be included in the
final report.

Important:
    These measurements are not meant to compete with optimized cryptographic
    libraries. This is a pure Python educational implementation, so it is
    expected to be slower than production-grade implementations written in C,
    Rust, or assembly.
"""

import statistics
import time

from src.key_exchange import X25519Party


# ---------------------------------------------------------------------------
# Benchmark configuration
# ---------------------------------------------------------------------------

# Number of repetitions for each benchmark.
# A larger number gives a more stable average.
ITERATIONS = 1000


# ---------------------------------------------------------------------------
# Timing helper
# ---------------------------------------------------------------------------

def measure_average_time(operation, iterations: int = ITERATIONS) -> tuple[float, float, float]:
    """
    Measure the execution time of a repeated operation.

    Args:
        operation:
            A function with no arguments that performs the operation
            we want to measure.

        iterations:
            Number of times to run the operation.

    Returns:
        A tuple containing:
            - average time in milliseconds
            - minimum time in milliseconds
            - maximum time in milliseconds

    Why this helper exists:
        We benchmark several operations in the same way. This function keeps
        the benchmark code clean and consistent.
    """
    timings = []

    for _ in range(iterations):
        start_time = time.perf_counter()
        operation()
        end_time = time.perf_counter()

        elapsed_ms = (end_time - start_time) * 1000
        timings.append(elapsed_ms)

    average_ms = statistics.mean(timings)
    minimum_ms = min(timings)
    maximum_ms = max(timings)

    return average_ms, minimum_ms, maximum_ms


# ---------------------------------------------------------------------------
# Benchmark operations
# ---------------------------------------------------------------------------

def benchmark_party_creation() -> tuple[float, float, float]:
    """
    Measure the time required to create one X25519 party.

    Creating a party includes:
        1. generating a random 32-byte private key
        2. deriving the public key using X25519(private_key, BASE_POINT)

    In the report, this can be described as public key generation time.
    """
    return measure_average_time(lambda: X25519Party("Benchmark Party"))


def benchmark_shared_secret_derivation() -> tuple[float, float, float]:
    """
    Measure the time required to derive one shared secret.

    We create Alice and Bob once, then repeatedly measure only Alice deriving
    the shared secret from Bob's public key.

    This avoids mixing key generation time into the shared-secret measurement.
    """
    alice = X25519Party("Alice")
    bob = X25519Party("Bob")

    return measure_average_time(lambda: alice.derive_shared_secret(bob.public_key))


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_benchmark_result(name: str, result: tuple[float, float, float]) -> None:
    """
    Print one benchmark result in a readable format.

    Args:
        name:
            Name of the benchmark operation.

        result:
            Tuple of average, minimum, and maximum time in milliseconds.
    """
    average_ms, minimum_ms, maximum_ms = result

    print(f"{name}")
    print(f"  Average: {average_ms:.6f} ms")
    print(f"  Min:     {minimum_ms:.6f} ms")
    print(f"  Max:     {maximum_ms:.6f} ms")
    print()


def print_key_sizes() -> None:
    """
    Print the fixed sizes used by X25519.

    X25519 uses:
        - 32-byte private keys
        - 32-byte public keys
        - 32-byte shared secrets

    These values are useful for the final report comparison section.
    """
    sample_party = X25519Party("Sample")

    other_party = X25519Party("Other")
    shared_secret = sample_party.derive_shared_secret(other_party.public_key)

    print("Key and Shared Secret Sizes")
    print("---------------------------")
    print(f"Private key size:      {len(sample_party.private_key)} bytes")
    print(f"Public key size:       {len(sample_party.public_key)} bytes")
    print(f"Shared secret size:    {len(shared_secret)} bytes")
    print()


# ---------------------------------------------------------------------------
# Main benchmark runner
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Run all X25519 benchmarks and print the results.
    """
    print("X25519 Benchmark")
    print("================")
    print(f"Iterations per benchmark: {ITERATIONS}")
    print()

    print_key_sizes()

    party_creation_result = benchmark_party_creation()
    shared_secret_result = benchmark_shared_secret_derivation()

    print("Timing Results")
    print("--------------")
    print_benchmark_result("Party creation / public key generation", party_creation_result)
    print_benchmark_result("Shared secret derivation", shared_secret_result)


if __name__ == "__main__":
    main()