#!/usr/bin/env python3
"""Independent verifier for zeroj-r1cs-canonical-v1 cache files.

This implementation intentionally shares no ZeroJ/JVM parsing or hashing code. It validates the
strict ZJRF v1 envelope, CSR invariants, exact fingerprint dimensions, and recomputes the
domain-separated canonical relation SHA-256 directly from the file-backed matrices.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


MAGIC = 0x5A4A5246
VERSION = 1
DOMAIN = b"zeroj-r1cs-canonical-v1\x00"
MAX_DICTIONARY_ENTRIES = 1 << 20
BLS12_381_SCALAR_MODULUS = int(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16
)
EXACT = re.compile(
    rb"c([1-9][0-9]*)-w([1-9][0-9]*)-p(0|[1-9][0-9]*)-r([0-9a-f]{64})\Z"
)


class InvalidR1CS(ValueError):
    pass


@dataclass(frozen=True)
class Matrix:
    nnz: int
    offsets: int
    wires: int
    coefficients: int


def u16(data: mmap.mmap, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: mmap.mmap, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def require_range(position: int, length: int, limit: int, label: str) -> None:
    if position < 0 or length < 0 or position > limit or length > limit - position:
        raise InvalidR1CS(f"truncated or oversized {label}")


def parse_matrix(data: mmap.mmap, position: int, rows: int, limit: int) -> tuple[Matrix, int]:
    require_range(position, 4, limit, "matrix nnz")
    nnz = u32(data, position)
    position += 4
    offsets_bytes = (rows + 1) * 4
    indices_bytes = nnz * 4
    matrix_bytes = offsets_bytes + indices_bytes * 2
    require_range(position, matrix_bytes, limit, "matrix payload")
    matrix = Matrix(
        nnz=nnz,
        offsets=position,
        wires=position + offsets_bytes,
        coefficients=position + offsets_bytes + indices_bytes,
    )

    previous = 0
    for row in range(rows):
        start = u32(data, matrix.offsets + row * 4)
        end = u32(data, matrix.offsets + (row + 1) * 4)
        if start != previous or end < start or end > nnz:
            raise InvalidR1CS("malformed CSR row offsets")
        previous = end
    if previous != nnz:
        raise InvalidR1CS("unreachable trailing matrix terms")
    return matrix, position + matrix_bytes


def verify(path: Path, expected_fingerprint: str | None) -> dict[str, object]:
    if not path.is_file():
        raise InvalidR1CS(f"not a regular file: {path}")
    size = path.stat().st_size
    if size < 18 or size > 0x7FFFFFFF:
        raise InvalidR1CS("file size is outside the ZJRF v1 bounds")

    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        if u32(data, 0) != MAGIC or u32(data, 4) != VERSION:
            raise InvalidR1CS("wrong magic or version")
        fingerprint_length = u16(data, 8)
        position = 10
        require_range(position, fingerprint_length + 8, size, "header")
        fingerprint_bytes = data[position : position + fingerprint_length]
        position += fingerprint_length
        match = EXACT.fullmatch(fingerprint_bytes)
        if match is None:
            raise InvalidR1CS("header does not contain an exact R1CS fingerprint")
        fingerprint = fingerprint_bytes.decode("ascii")
        if expected_fingerprint is not None and fingerprint != expected_fingerprint:
            raise InvalidR1CS("header fingerprint differs from --expected-fingerprint")

        constraints = int(match.group(1))
        wires = int(match.group(2))
        public_inputs = int(match.group(3))
        expected_digest = match.group(4).decode("ascii")
        if public_inputs >= wires:
            raise InvalidR1CS("public input count must be smaller than wire count")

        rows = u32(data, position)
        dictionary_size = u32(data, position + 4)
        position += 8
        if rows != constraints:
            raise InvalidR1CS("row count differs from exact fingerprint")
        if dictionary_size > MAX_DICTIONARY_ENTRIES:
            raise InvalidR1CS("coefficient dictionary exceeds the v1 bound")

        matrices: list[Matrix] = []
        total_nnz = 0
        for _ in range(3):
            matrix, position = parse_matrix(data, position, rows, size)
            matrices.append(matrix)
            total_nnz += matrix.nnz

        dictionary_bytes = dictionary_size * 32
        require_range(position, dictionary_bytes, size, "coefficient dictionary")
        if dictionary_size > total_nnz:
            raise InvalidR1CS("dictionary has more entries than all matrix terms")
        if position + dictionary_bytes != size:
            raise InvalidR1CS("trailing bytes after coefficient dictionary")
        dictionary = position
        for index in range(dictionary_size):
            coefficient_offset = dictionary + index * 32
            coefficient = int.from_bytes(
                data[coefficient_offset : coefficient_offset + 32], "big"
            )
            if coefficient >= BLS12_381_SCALAR_MODULUS:
                raise InvalidR1CS(
                    f"coefficient dictionary entry {index} is not a canonical BLS12-381 scalar"
                )

        digest = hashlib.sha256()
        digest.update(DOMAIN)
        digest.update(struct.pack("<III", rows, wires, public_inputs))
        for matrix in matrices:
            for row in range(rows):
                start = u32(data, matrix.offsets + row * 4)
                end = u32(data, matrix.offsets + (row + 1) * 4)
                digest.update(struct.pack("<I", end - start))
                previous_wire = -1
                for index in range(start, end):
                    wire = u32(data, matrix.wires + index * 4)
                    coefficient = u32(data, matrix.coefficients + index * 4)
                    if wire >= wires or wire <= previous_wire:
                        raise InvalidR1CS("matrix wires are out of range or not strictly sorted")
                    if coefficient >= dictionary_size:
                        raise InvalidR1CS("matrix coefficient index is outside the dictionary")
                    previous_wire = wire
                    digest.update(struct.pack("<I", wire))
                    coefficient_offset = dictionary + coefficient * 32
                    digest.update(data[coefficient_offset : coefficient_offset + 32])

        actual_digest = digest.hexdigest()
        if actual_digest != expected_digest:
            raise InvalidR1CS(
                f"canonical digest mismatch: expected {expected_digest}, computed {actual_digest}"
            )
        return {
            "schema": "zeroj-r1cs-independent-check-v1",
            "path": str(path.resolve()),
            "fingerprint": fingerprint,
            "r1csSha256": actual_digest,
            "constraints": rows,
            "wires": wires,
            "publicInputs": public_inputs,
            "dictionaryEntries": dictionary_size,
            "matrixNnz": [matrix.nnz for matrix in matrices],
            "valid": True,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("r1cs", type=Path, help="ZeroJ r1cs.bin cache")
    parser.add_argument("--expected-fingerprint", help="exact c...-w...-p...-r... identity")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    try:
        result = verify(args.r1cs, args.expected_fingerprint)
    except (InvalidR1CS, OSError, OverflowError, UnicodeError, struct.error) as error:
        if args.json:
            print(json.dumps({"valid": False, "error": str(error)}, sort_keys=True))
        else:
            print(f"INVALID: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"VALID {result['fingerprint']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
