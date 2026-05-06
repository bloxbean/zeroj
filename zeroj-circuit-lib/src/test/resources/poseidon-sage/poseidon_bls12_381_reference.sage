#!/usr/bin/env sage
# SageMath reference implementation of Poseidon over BLS12-381 scalar field
# with paper-canonical parameters t=3, α=5, RF=8, RP=57.
#
# The constants generator is a verbatim port of hadeshash's Grain LFSR
# (generate_parameters_grain.sage), pinned commit
# 208b5a164c6a252b137997694d90931b2bb851c5. The permutation mirrors the
# Poseidon paper (Grassi et al., 2021) §4.
#
# Purpose: produce `Poseidon_BLS12_381(a, b) = h` test vectors from an
# independent external implementation for cross-verification against ZeroJ's
# pure-Java PoseidonHash. See ADR-0015.
#
# Run via:
#   docker run --rm --platform linux/amd64 \
#       -v "$(pwd)/zeroj-circuit-lib/src/test/resources/poseidon-sage:/work" \
#       sagemath/sagemath:latest \
#       sage /work/poseidon_bls12_381_reference.sage

# --- Parameters (BLS12-381, t=3, alpha=5, RF=8, RP=57) ---
PRIME = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
FIELD_SIZE = 255
NUM_CELLS = 3
ALPHA = 5
R_F = 8
R_P = 57

F = GF(PRIME)

# ---- Grain LFSR (verbatim port) ----
INIT_SEQUENCE = []

def grain_sr_generator():
    bit_sequence = INIT_SEQUENCE
    for _ in range(0, 160):
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)
    while True:
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)
        while new_bit == 0:
            new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
            bit_sequence.pop(0)
            bit_sequence.append(new_bit)
            new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
            bit_sequence.pop(0)
            bit_sequence.append(new_bit)
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)
        yield new_bit

grain_gen = None

def grain_random_bits(num_bits):
    bits = [next(grain_gen) for _ in range(num_bits)]
    return int("".join(str(b) for b in bits), 2)

def init_generator():
    global INIT_SEQUENCE, grain_gen
    bit_list_field = [_ for _ in bin(1)[2:].zfill(2)]  # GF(p) = 1
    bit_list_sbox  = [_ for _ in bin(0)[2:].zfill(4)]  # x^alpha = 0
    bit_list_n     = [_ for _ in bin(FIELD_SIZE)[2:].zfill(12)]
    bit_list_t     = [_ for _ in bin(NUM_CELLS)[2:].zfill(12)]
    bit_list_RF    = [_ for _ in bin(R_F)[2:].zfill(10)]
    bit_list_RP    = [_ for _ in bin(R_P)[2:].zfill(10)]
    bit_list_1     = [1] * 30
    INIT_SEQUENCE = bit_list_field + bit_list_sbox + bit_list_n + bit_list_t + bit_list_RF + bit_list_RP + bit_list_1
    INIT_SEQUENCE = [int(b) for b in INIT_SEQUENCE]
    grain_gen = grain_sr_generator()

def generate_constants():
    constants = []
    num_constants = (R_F + R_P) * NUM_CELLS
    for _ in range(num_constants):
        v = grain_random_bits(FIELD_SIZE)
        while v >= PRIME:
            v = grain_random_bits(FIELD_SIZE)
        constants.append(v)
    return constants

def create_mds_p():
    while True:
        flag = True
        rand_list = [F(grain_random_bits(FIELD_SIZE)) for _ in range(2 * NUM_CELLS)]
        while len(rand_list) != len(set(rand_list)):
            rand_list = [F(grain_random_bits(FIELD_SIZE)) for _ in range(2 * NUM_CELLS)]
        xs = rand_list[:NUM_CELLS]
        ys = rand_list[NUM_CELLS:]
        M = matrix(F, NUM_CELLS, NUM_CELLS)
        for i in range(NUM_CELLS):
            for j in range(NUM_CELLS):
                if (not flag) or ((xs[i] + ys[j]) == 0):
                    flag = False
                else:
                    M[i, j] = (xs[i] + ys[j]) ^ (-1)
        if flag:
            return M

# ---- Poseidon permutation (t=3, alpha=5) ----
def poseidon(a, b, C, M):
    state = [F(0), F(a), F(b)]
    for r in range(R_F + R_P):
        # AddRoundConstants
        for j in range(NUM_CELLS):
            state[j] = state[j] + F(C[r * NUM_CELLS + j])
        # S-box (x^5)
        if r < R_F // 2 or r >= R_F // 2 + R_P:
            for j in range(NUM_CELLS):
                state[j] = state[j] ^ ALPHA
        else:
            state[0] = state[0] ^ ALPHA
        # MDS
        new_state = [F(0)] * NUM_CELLS
        for i in range(NUM_CELLS):
            for j in range(NUM_CELLS):
                new_state[i] = new_state[i] + M[i, j] * state[j]
        state = new_state
    return state[0]

# ---- Main ----
init_generator()
C = generate_constants()
M = create_mds_p()

print("=== Grain LFSR output (first 6 round constants) ===")
for i in range(6):
    print("  C[%d] = 0x%s" % (i, hex(C[i])[2:] if str(hex(C[i]))[:2] != "0x" else hex(C[i])[2:]))

print("=== MDS matrix ===")
for i in range(3):
    for j in range(3):
        print("  M[%d][%d] = 0x%s" % (i, j, hex(int(M[i, j]))[2:]))

print("=== Poseidon_BLS12_381(a, b) test vectors ===")
for (a, b) in [(0, 0), (1, 2), (123, 456)]:
    h = poseidon(a, b, C, M)
    print("  Poseidon(%d, %d) = 0x%s" % (a, b, hex(int(h))[2:]))
