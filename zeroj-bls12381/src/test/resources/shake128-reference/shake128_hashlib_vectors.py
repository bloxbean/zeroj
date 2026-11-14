"""Generates shake128-hashlib-v1.json: SHAKE128 outputs from CPython's hashlib (ADR-0061 I12).

hashlib.shake_128 wraps an implementation ZeroJ did not write (HACL* in CPython 3.12+, or OpenSSL),
so these outputs are external evidence for zeroj-bls12381's Shake128. Run with:

    python3 -I -B shake128_hashlib_vectors.py > shake128-hashlib-v1.json

Message i has length LENGTHS[i] and octets (7*j + 3) mod 256; each output is OUTPUT_LENGTH octets.
"""
import hashlib
import json
import platform
import sys

LENGTHS = [0, 1, 2, 31, 32, 135, 136, 137, 167, 168, 169, 200, 335, 336, 337, 503, 504, 505, 1000, 4096]
OUTPUT_LENGTH = 520


def message(n):
    return bytes((7 * j + 3) % 256 for j in range(n))


def main():
    cases = [{"messageLength": str(n), "outputHex": hashlib.shake_128(message(n)).hexdigest(OUTPUT_LENGTH)}
             for n in LENGTHS]
    json.dump({"schema": "zeroj-shake128-hashlib-v1",
               "generator": {"python": platform.python_version(), "implementation": sys.implementation.name},
               "messageRule": "(7*j + 3) mod 256",
               "outputLength": str(OUTPUT_LENGTH),
               "cases": cases}, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
