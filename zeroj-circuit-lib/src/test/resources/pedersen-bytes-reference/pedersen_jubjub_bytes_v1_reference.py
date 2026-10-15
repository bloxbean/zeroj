#!/usr/bin/env python3
"""Independent reference implementation of the ZeroJ `pedersen-jubjub-bytes-v1` profile.

Written from docs/specs/pedersen-jubjub-bytes-v1.md (primary), docs/specs/pedersen-jubjub-v1.md,
docs/specs/jubjub-eddsa-v1.md section 1 and the text of RFC 9380 only. The bases G and H are
taken from the sibling independent reference ../pedersen-reference/pedersen_jubjub_v1_reference.py
(imported, not copied) and compared with the values pinned in pedersen-jubjub-v1.md. No ZeroJ
Java source was read. See README.md in this directory.

Python 3 standard library only. Run in this directory:

    python3 -B pedersen_jubjub_bytes_v1_reference.py

The script prints key=value lines to stdout and writes the same lines to reference-output.txt
next to this file.

Exit status: 0 every check passed; 1 a check, spec comparison or negative vector failed
(failing keys go to stderr); 2 the RFC 9380 Appendix K.1 expand_message_xmd self-check failed.
"""

import hashlib
import os
import platform
import sys

sys.dont_write_bytecode = True  # never leave __pycache__ next to the sibling reference

HERE = os.path.dirname(os.path.abspath(__file__))
SIBLING_DIR = os.path.normpath(os.path.join(HERE, "..", "pedersen-reference"))
OUTPUT_FILE = os.path.join(HERE, "reference-output.txt")
SCRIPT_NAME = "pedersen_jubjub_bytes_v1_reference.py"
SPEC_PATH = "docs/specs/pedersen-jubjub-bytes-v1.md"
SPEC_FILE = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "..", SPEC_PATH))


def file_sha256(path):
    """Content hash for the provenance header; 'unavailable' if the file cannot be read."""
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return "unavailable"


def sha256_backend():
    """Which hashlib implementation backs sha256: '_hashlib' is OpenSSL, otherwise builtin."""
    module = type(hashlib.sha256()).__module__
    if module == "_hashlib":
        import ssl
        return "hashlib OpenSSL (%s; %s)" % (hashlib.sha256.__name__, ssl.OPENSSL_VERSION)
    return "hashlib builtin (%s.%s)" % (module, type(hashlib.sha256()).__name__)

# The sibling's main() is guarded by `if __name__ == "__main__"`, so importing it neither runs
# it nor rewrites its reference-output.txt. Only its Poseidon/H derivation and its affine
# arithmetic (as an independent differential for the commitment) are used.
sys.path.insert(0, SIBLING_DIR)
import pedersen_jubjub_v1_reference as sib  # noqa: E402

sys.path.pop(0)

# --------------------------------------------------------------------------------------------
# Constants, transcribed by hand from the specs
# --------------------------------------------------------------------------------------------

# pedersen-jubjub-v1.md section 1 / jubjub-eddsa-v1.md section 1
P = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
L_ORDER = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7
D = 0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1
A = P - 1

# pedersen-jubjub-bytes-v1.md section 2
DST = b"ZeroJ-pedersen-jubjub-bytes-v1-H2S-XMD:SHA-256"
LEN_U = 48  # L in the spec; named LEN_U here to avoid a clash with the group order l
MAX_PAYLOAD_BYTES = 2 ** 61 - 256

# Values pinned in the specs. Comparison targets only, never inputs.
SPEC_PIN = {
    "dst_len": 46,
    "dst_hex": "5a65726f4a2d706564657273656e2d6a75626a75622d62797465732d76312d4832532d584d443a5348412d323536",
    "dst_prime_len": 47,
    "L": 48,
    "max_payload_bytes": 2305843009213693696,
    "b0_frame_overhead": 122,
    # pedersen-jubjub-v1.md section 2.1, 2.3, 8
    "g_u": 0x3EA5C4673A121CA35ED37EE3B172F5EE04315C657FBE375F512DFEA318D56FE5,
    "g_v": 0x57137B83EA6EDB4F78F7D30D3F616CB3B9AA6E8E40808413C10CEA38D50C55CB,
    "g_encoding": "cb550cd538ea0cc1138480408e6eaab9b36c613f0dd3f7784fdb6eea837b13d7",
    "h_u": 0x72963E7766B3CD553A1525A17DA810E6B4CDEB70541DAC5B52A3210F5C372DB6,
    "h_v": 0x60BB97D81759E04503194AEB9EB8FAA23B0092C941D1139BFE99907794C8E37D,
    "h_encoding": "7de3c894779099fe9b13d141c992003ba2fab89eeb4a190345e05917d897bb60",
    "c_42_12345_u": 0x478A0BD6A0EEBDFFC610618AD979B39D6237F240125534886D38720CBD76A025,
    "c_42_12345_v": 0x6387C33BE7B7177B74CE909592456D7C81DAB375A6BA3182EB7F5E2974E0D357,
    "c_42_12345_encoding": "57d3e074295e7feb8231baa675b3da817c6d45929590ce747b17b7e73bc387e3",
}

# RFC 9380 Appendix K.1, copied from https://www.rfc-editor.org/rfc/rfc9380.txt
K1_DST = b"QUUX-V01-CS02-with-expander-SHA256-128"
K1_VECTORS = [
    ("empty_0x20", b"", 0x20,
     "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"),
    ("abc_0x20", b"abc", 0x20,
     "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"),
    ("abcdef0123456789_0x20", b"abcdef0123456789", 0x20,
     "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1"),
    ("empty_0x80", b"", 0x80,
     "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbe"
     "e0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18"
     "eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dc"
     "c541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"),
    ("abc_0x80", b"abc", 0x80,
     "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a"
     "647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635"
     "bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00"
     "058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"),
    ("abcdef0123456789_0x80", b"abcdef0123456789", 0x80,
     "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9"
     "ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4b"
     "c95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be1"
     "4cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df"),
    ("q128_0x20", b"q128_" + b"q" * 128, 0x20,
     "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9"),
    ("a512_0x20", b"a512_" + b"a" * 512, 0x20,
     "4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c"),
    ("q128_0x80", b"q128_" + b"q" * 128, 0x80,
     "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bb"
     "d88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0"
     "e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b"
     "29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a"),
    ("a512_0x80", b"a512_" + b"a" * 512, 0x80,
     "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d0"
     "6d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608"
     "ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4"
     "a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487"),
]

# Known answers inlined in pedersen-jubjub-bytes-v1.md section 10 (transcribed by hand; they
# were copied into the spec from an earlier run of this script, so they guard the spec text and
# later runs, not the algorithm).
SPEC10 = {
    "empty_n": 0,
    "empty_b0": "d8a576b8db82c95dac7246e17f5cee19e4aa715e06e0c6a7f26b8c30aec62481",
    "empty_uniform": "0806e94e86b0513631c07b6aba359c462afe5fae6338f2b8a9f8f9070c67b61f"
                     "c8b5cd7a9ee1f3d2739001762e0b7f17",
    "empty_s": 0x061F05A7E9920513846BC5F0DD366C71A5ED2C35C6CDC88BA6F71D0F355F4181,
    "zero1_s": 0x0DCA70C85AE4D9C8E22F6FF09A66FD81291C89763679C0C4ACC2957942B53294,
    "utf8_text_s": 0x01021BCE20E1CA8D71CC9CE2BBE988EEE0335A559A8E7E65574E1049224D674F,
    "empty_c_r0_encode": "9f0d942a712d02e78959e4899908bfd3d8fff8f871f42ae4ace3d1f336e9789d",
    "empty_c_r1_encode": "0f2b6778c98d4623d8312c6d7cb02dc7892ce94927c04dd064adcfb7e7912489",
    "utf8_text_c_r1_encode": "4e66485131af3603f96f18003966a30793f1c78492c27d644c1e12d0a941852d",
}
# Expected input for neg_v_ge_p_alias_identity, as supplied in the review request.
EXPECTED_V_GE_P_ALIAS_IDENTITY = "02000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73"
# DST_prime for K.1, also copied from the RFC (checks I2OSP(len(DST), 1)).
K1_DST_PRIME_HEX = ("515555582d5630312d435330322d776974682d657870616e6465"
                    "722d5348413235362d31323826")

# Fixed test blindings (task definition). Not hiding blindings (spec section 8).
R1 = L_ORDER - 1
R2_RAW = 0x0C0FFEE0DDBA11DEADBEEFCAFEF00D5EED0123456789ABCDEFFEDCBA98765432


class InputRejected(ValueError):
    pass


# --------------------------------------------------------------------------------------------
# RFC 9380 primitives
# --------------------------------------------------------------------------------------------

def i2osp(x, k):
    if x < 0 or x >= 256 ** k:
        raise ValueError("I2OSP: integer too large")
    return x.to_bytes(k, "big")


def os2ip(s):
    return int.from_bytes(s, "big")


def strxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def expand_message_xmd(msg, dst, len_in_bytes):
    """RFC 9380 section 5.3.1 with H = SHA-256. Returns (uniform_bytes, [b_0, b_1, ...])."""
    b_in_bytes, s_in_bytes = 32, 64
    ell = -(-len_in_bytes // b_in_bytes)
    if ell > 255 or len_in_bytes > 65535 or len(dst) > 255:
        raise ValueError("expand_message_xmd: ABORT")
    dst_prime = dst + i2osp(len(dst), 1)
    z_pad = i2osp(0, s_in_bytes)
    l_i_b_str = i2osp(len_in_bytes, 2)
    msg_prime = z_pad + msg + l_i_b_str + i2osp(0, 1) + dst_prime
    b = [hashlib.sha256(msg_prime).digest()]
    b.append(hashlib.sha256(b[0] + i2osp(1, 1) + dst_prime).digest())
    for i in range(2, ell + 1):
        b.append(hashlib.sha256(strxor(b[0], b[i - 1]) + i2osp(i, 1) + dst_prime).digest())
    uniform = b"".join(b[1:])
    return uniform[:len_in_bytes], b


# --------------------------------------------------------------------------------------------
# pedersen-jubjub-bytes-v1 section 3: HashBytesToScalar
# --------------------------------------------------------------------------------------------

def hash_bytes_to_scalar(payload):
    """Section 3.1 via generic RFC 9380 hash_to_field (count = 1, m = 1, field GF(l)).
    Returns dict with n, b0, b1, b2, u, s."""
    n = len(payload)
    if n > MAX_PAYLOAD_BYTES:
        raise InputRejected("payload longer than MAX_PAYLOAD_BYTES")
    msg = payload + i2osp(n, 8)  # length as an 8-octet big-endian suffix
    uniform, b = expand_message_xmd(msg, DST, LEN_U)  # count * m * L = 48
    tv = uniform[0:LEN_U]
    s = os2ip(tv) % L_ORDER
    return {"n": n, "b0": b[0], "b1": b[1], "b2": b[2], "u": tv, "s": s}


def hash_bytes_to_scalar_octet_form(payload):
    """Section 3.1 'equivalently, octet by octet', written independently of the above."""
    n = len(payload)
    tail = DST + bytes([0x2E])
    b0 = hashlib.sha256(bytes(64) + payload + n.to_bytes(8, "big")
                        + bytes([0x00, 0x30]) + bytes([0x00]) + tail).digest()
    b1 = hashlib.sha256(b0 + bytes([0x01]) + tail).digest()
    b2 = hashlib.sha256(bytes(x ^ y for x, y in zip(b0, b1)) + bytes([0x02]) + tail).digest()
    u = b1 + b2[:16]
    return int.from_bytes(u, "big") % L_ORDER


def hash_bytes_to_scalar_streaming(payload, chunk):
    """Section 6.1: one pass, length appended after the last octet, read boundaries irrelevant."""
    tail = DST + bytes([len(DST)])
    h0 = hashlib.sha256()
    h0.update(bytes(64))
    n = 0
    for i in range(0, len(payload), chunk):
        piece = payload[i:i + chunk]
        h0.update(piece)
        n += len(piece)
    h0.update(n.to_bytes(8, "big"))
    h0.update((48).to_bytes(2, "big") + b"\x00" + tail)
    b0 = h0.digest()
    b1 = hashlib.sha256(b0 + b"\x01" + tail).digest()
    b2 = hashlib.sha256(strxor(b0, b1) + b"\x02" + tail).digest()
    return int.from_bytes(b1 + b2[:16], "big") % L_ORDER


# --------------------------------------------------------------------------------------------
# Mutated variants (section D). Each is a separate function; none is a flag on the real one.
# --------------------------------------------------------------------------------------------

def _sha(x):
    return hashlib.sha256(x).digest()


def mut_dst_lowercase(B):
    dp = DST.lower() + bytes([len(DST)])
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_dst_sha512_label(B):
    dst = b"ZeroJ-pedersen-jubjub-bytes-v1-H2S-XMD:SHA-512"
    dp = dst + bytes([len(dst)])
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_length_prefix(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + len(B).to_bytes(8, "big") + B + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_length_le(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "little") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_no_length(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_no_zpad(B):
    dp = DST + b"\x2e"
    b0 = _sha(B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_zpad128(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(128) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_len64(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x40\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2) % L_ORDER  # 64-octet u


def mut_sha512(B):
    # expand_message_xmd with SHA-512: b_in_bytes = 64, s_in_bytes = 128, ell = 1.
    dp = DST + b"\x2e"
    b0 = hashlib.sha512(bytes(128) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp).digest()
    b1 = hashlib.sha512(b0 + b"\x01" + dp).digest()
    return os2ip(b1[:48]) % L_ORDER


def mut_no_xor(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(b1 + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_b0_slice(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    return os2ip(b0 + b1[:16]) % L_ORDER


def mut_first48_wrong(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b2 + b1[:16]) % L_ORDER


def mut_mod_p(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % P


def mut_signed(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return int.from_bytes(b1 + b2[:16], "big", signed=True) % L_ORDER  # Python % is non-negative


def mut_b1_counter_zero(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x00" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_b2_counter_one(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x01" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_b1_only(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    return os2ip(b1) % L_ORDER  # 32-octet uniform_bytes


def mut_no_separator(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_lib_le(B):
    dp = DST + b"\x2e"
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x30\x00" + b"\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


def mut_dst_prime_no_len(B):
    dp = DST  # no I2OSP(len(DST), 1)
    b0 = _sha(bytes(64) + B + len(B).to_bytes(8, "big") + b"\x00\x30\x00" + dp)
    b1 = _sha(b0 + b"\x01" + dp)
    b2 = _sha(strxor(b0, b1) + b"\x02" + dp)
    return os2ip(b1 + b2[:16]) % L_ORDER


MUTATIONS = [
    ("b1_counter_zero", mut_b1_counter_zero),
    ("b2_counter_one", mut_b2_counter_one),
    ("b1_only", mut_b1_only),
    ("no_separator", mut_no_separator),
    ("lib_le", mut_lib_le),
    ("dst_prime_no_len", mut_dst_prime_no_len),
    ("dst_lowercase", mut_dst_lowercase),
    ("dst_sha512_label", mut_dst_sha512_label),
    ("length_prefix", mut_length_prefix),
    ("length_le", mut_length_le),
    ("no_length", mut_no_length),
    ("no_zpad", mut_no_zpad),
    ("zpad128", mut_zpad128),
    ("len64", mut_len64),
    ("sha512", mut_sha512),
    ("no_xor", mut_no_xor),
    ("b0_slice", mut_b0_slice),
    ("first48_wrong", mut_first48_wrong),
    ("mod_p", mut_mod_p),
    ("signed", mut_signed),
]

# --------------------------------------------------------------------------------------------
# Jubjub arithmetic, written here in extended twisted-Edwards coordinates (X:Y:T:Z), with the
# unified addition of Hisil-Wong-Carter-Dawson 2008 for general a. This is deliberately a
# different formulation from the sibling's affine arithmetic, so the two act as a differential.
# Coordinates: u = X/Z, v = Y/Z, T = XY/Z; curve a*u^2 + v^2 = 1 + d*u^2*v^2 with a = -1.
# --------------------------------------------------------------------------------------------

def finv(x):
    x %= P
    if x == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(x, P - 2, P)


EXT_IDENTITY = (0, 1, 0, 1)


def to_ext(pt):
    u, v = pt
    return (u % P, v % P, u * v % P, 1)


def to_affine(e):
    X, Y, _T, Z = e
    zi = finv(Z)
    return (X * zi % P, Y * zi % P)


def ext_add(e1, e2):
    X1, Y1, T1, Z1 = e1
    X2, Y2, T2, Z2 = e2
    a_ = X1 * X2 % P
    b_ = Y1 * Y2 % P
    c_ = T1 * D % P * T2 % P
    d_ = Z1 * Z2 % P
    e_ = ((X1 + Y1) * (X2 + Y2) - a_ - b_) % P
    f_ = (d_ - c_) % P
    g_ = (d_ + c_) % P
    h_ = (b_ - A * a_) % P
    return (e_ * f_ % P, g_ * h_ % P, e_ * h_ % P, f_ * g_ % P)


def ext_mul(k, e):
    """Right-to-left double-and-add using only the unified addition."""
    if k < 0:
        raise ValueError("negative scalar")
    acc, base = EXT_IDENTITY, e
    while k:
        if k & 1:
            acc = ext_add(acc, base)
        base = ext_add(base, base)
        k >>= 1
    return acc


def ext_is_identity(e):
    X, Y, _T, Z = e
    return Z % P != 0 and X % P == 0 and (Y - Z) % P == 0


def on_curve(pt):
    u, v = pt
    uu, vv = u * u % P, v * v % P
    return (A * uu + vv - 1 - D * uu * vv) % P == 0


def in_prime_subgroup(pt):
    return ext_is_identity(ext_mul(L_ORDER, to_ext(pt)))


def small_order(pt, bound=8):
    """Least k in 1..bound with [k]pt = identity, or None."""
    e = to_ext(pt)
    acc = EXT_IDENTITY
    for k in range(1, bound + 1):
        acc = ext_add(acc, e)
        if ext_is_identity(acc):
            return k
    return None


def legendre_is_square(x):
    x %= P
    return x == 0 or pow(x, (P - 1) // 2, P) == 1


def fsqrt(n):
    """Tonelli-Shanks for p - 1 = q * 2^s. Returns a root or None."""
    n %= P
    if n == 0:
        return 0
    if not legendre_is_square(n):
        return None
    q, s = P - 1, 0
    while q % 2 == 0:
        q, s = q // 2, s + 1
    z = 2
    while legendre_is_square(z):
        z += 1
    m, c, t, r = s, pow(z, q, P), pow(n, q, P), pow(n, (q + 1) // 2, P)
    while t != 1:
        i, tt = 0, t
        while tt != 1:
            tt = tt * tt % P
            i += 1
        b = pow(c, 1 << (m - i - 1), P)
        m, c, t, r = i, b * b % P, t * b * b % P, r * b % P
    assert r * r % P == n
    return r


def encode(pt):
    """pedersen-jubjub-v1 section 4."""
    u, v = pt
    out = bytearray(v.to_bytes(32, "little"))
    if u % 2 == 1:
        out[31] |= 0x80
    return bytes(out)


def decode(data):
    """pedersen-jubjub-v1 section 4, rules 1-5. Returns (point, None) or (None, reason)."""
    if len(data) != 32:
        return None, "length"
    sign = (data[31] >> 7) & 1
    v = int.from_bytes(data[:31] + bytes([data[31] & 0x7F]), "little")
    if v >= P:
        return None, "v_ge_p"
    vv = v * v % P
    den = (D * vv + 1) % P
    if den == 0:
        return None, "denominator_zero"
    w = (vv - 1) * finv(den) % P
    u = fsqrt(w)
    if u is None:
        return None, "non_square"
    if u == 0 and sign == 1:
        return None, "u_zero_sign_set"
    if u % 2 != sign:
        u = P - u
    return (u, v), None


def receive_with_v_reduced_mod_p(data):
    """NOT the profile: a deliberately lenient decoder that reduces v mod p instead of
    rejecting v >= p. Used only to show that an alias is rejected by rule 2 alone."""
    sign = data[31] & 0x80
    v = int.from_bytes(data[:31] + bytes([data[31] & 0x7F]), "little") % P
    canonical = bytearray(v.to_bytes(32, "little"))
    canonical[31] |= sign
    return receive(bytes(canonical))


def receive(data):
    """pedersen-jubjub-v1 section 4.1 / bytes-v1 section 5: decode, then prime-order subgroup."""
    pt, reason = decode(data)
    if pt is None:
        return None, reason
    if not in_prime_subgroup(pt):
        return None, "not_in_prime_subgroup"
    return pt, None


# --------------------------------------------------------------------------------------------
# Commitment (bytes-v1 section 4)
# --------------------------------------------------------------------------------------------

def c_bytes(payload, r, G, H):
    if not (0 <= r < L_ORDER):  # rejected, not reduced
        raise InputRejected("blinding out of range")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise InputRejected("payload too long")
    s = hash_bytes_to_scalar(payload)["s"]
    e = ext_add(ext_mul(s, to_ext(G)), ext_mul(r, to_ext(H)))
    return to_affine(e)


def sibling_numeric_commit(v, r, G, H):
    """The numeric C(v, r) of pedersen-jubjub-v1 section 3, using the sibling's arithmetic
    (identical to the nested commit() in the sibling's main)."""
    return sib.point_add(sib.scalar_mul(v % sib.L, G), sib.scalar_mul(r % sib.L, H))


# --------------------------------------------------------------------------------------------
# Payloads
# --------------------------------------------------------------------------------------------

def pattern(n):
    return bytes((131 * i + 17) % 256 for i in range(n))


PATTERN_RECIPE = "payload[i] = (131*i + 17) mod 256 for i = 0..%d (%d octets)"


def payloads():
    out = [
        ("empty", b"", None),
        ("zero1", b"\x00", None),
        ("lead_zero", b"\x00\x00\x01", None),
        ("trail_zero", b"\x01\x00\x00", None),
        ("all_bytes", bytes(range(256)), "payload[i] = i for i = 0..255 (256 octets)"),
        ("nul_embedded", b"\x61\x00\x62", None),
        ("invalid_utf8", b"\xc3\x28", None),
        ("utf8_text", "Hello, ZeroJ ✓".encode("utf-8"), None),
        ("nfc_e", b"\xc3\xa9", None),
        ("nfd_e", b"\x65\xcc\x81", None),
        ("bom", b"\xef\xbb\xbf\x61", None),
    ]
    for n in (0, 1, 5, 6, 7, 55, 56, 60, 61, 62, 63, 64, 65, 119, 120, 125, 126, 127, 128,
              8191, 8192, 8193, 65536, 1048576):
        recipe = None if n <= 64 else PATTERN_RECIPE % (n - 1, n)
        out.append(("pattern_%d" % n, pattern(n), recipe))
    return out


# --------------------------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------------------------

def fe(x):
    return "0x%064x" % x


def tf(flag):
    return "true" if flag else "false"


def main():
    lines = []
    failures = []

    def out(key, value):
        lines.append("%s=%s" % (key, value))

    def check(key, flag):
        out(key, tf(flag))
        if not flag:
            failures.append(key)

    def finish(code):
        lines.append("result=%s" % ("pass" if code == 0 else "fail"))
        header = [
            "# pedersen-jubjub-bytes-v1 independent reference output (ADR-0058 M0).",
            "# Python: %s %s, standard library only" % (platform.python_implementation(),
                                                        platform.python_version()),
            "# SHA-256 backend: %s (interpreter-dependent)" % sha256_backend(),
            "# Script: %s (run in this directory)" % SCRIPT_NAME,
            "# Spec: %s (+ pedersen-jubjub-v1.md, jubjub-eddsa-v1.md section 1, RFC 9380)"
            % SPEC_PATH,
            "# sha256(%s)=%s" % (SCRIPT_NAME, file_sha256(os.path.abspath(__file__))),
            "# sha256(../pedersen-reference/pedersen_jubjub_v1_reference.py)=%s"
            % file_sha256(os.path.join(SIBLING_DIR, "pedersen_jubjub_v1_reference.py")),
            "# sha256(%s)=%s" % (SPEC_PATH, file_sha256(SPEC_FILE)),
            "# No ZeroJ Java source was read. See README.md.",
            "# Format: key=value. 0x + 64 hex = field element or scalar; bare hex = octet string;",
            "# integers decimal; booleans true/false.",
        ]
        text = "\n".join(header + lines) + "\n"
        sys.stdout.write(text)
        with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        if failures:
            sys.stderr.write("FAILED: %s\n" % ", ".join(failures))
        return code

    out("profile", "pedersen-jubjub-bytes-v1")

    # ---------------- A. RFC 9380 K.1 self-check (exit 2) ----------------
    k1_ok = True
    dst_prime_k1 = K1_DST + i2osp(len(K1_DST), 1)
    ok = dst_prime_k1.hex() == K1_DST_PRIME_HEX
    out("check_k1_dst_prime", tf(ok))
    k1_ok &= ok
    for name, msg, lib, expected in K1_VECTORS:
        got, _ = expand_message_xmd(msg, K1_DST, lib)
        ok = got.hex() == expected
        out("check_k1_%s" % name, tf(ok))
        k1_ok &= ok
    if not k1_ok:
        failures.append("check_k1_*")
        sys.stderr.write("RFC 9380 K.1 SELF-CHECK FAILED\n")
        return finish(2)

    # ---------------- A. constants against spec section 2 ----------------
    out("dst_ascii", DST.decode("ascii"))
    out("dst_hex", DST.hex())
    out("dst_prime_hex", (DST + i2osp(len(DST), 1)).hex())
    out("L", LEN_U)
    out("max_payload_bytes", MAX_PAYLOAD_BYTES)
    out("l", fe(L_ORDER))
    out("p", fe(P))
    check("check_spec_dst_len", len(DST) == SPEC_PIN["dst_len"])
    check("check_spec_dst_hex", DST.hex() == SPEC_PIN["dst_hex"])
    check("check_spec_dst_prime_len", len(DST) + 1 == SPEC_PIN["dst_prime_len"]
          and i2osp(len(DST), 1) == b"\x2e")
    log2_l = L_ORDER.bit_length()  # l is not a power of two, so ceil(log2 l) = bit_length
    check("check_spec_ceil_log2_l_252", log2_l == 252 and 2 ** 251 < L_ORDER < 2 ** 252)
    check("check_spec_L_48", LEN_U == SPEC_PIN["L"] and -(-(log2_l + 128) // 8) == 48)
    check("check_spec_max_payload_bytes", MAX_PAYLOAD_BYTES == SPEC_PIN["max_payload_bytes"])
    overhead = 64 + 8 + 2 + 1 + len(DST) + 1
    check("check_spec_b0_overhead_122", overhead == SPEC_PIN["b0_frame_overhead"])
    check("check_spec_max_b0_input_below_2pow61", MAX_PAYLOAD_BYTES + overhead < 2 ** 61)
    check("check_spec_bias_bound_below_2pow_minus132", L_ORDER * 2 ** 132 < 2 ** 384)
    check("check_spec_l_lt_p", L_ORDER < P)

    # ---------------- A. bases from the sibling, and C(42, 12345) ----------------
    check("check_sibling_constants_match", sib.P == P and sib.L == L_ORDER and sib.D == D)
    constants, mds = sib.poseidon_parameters()
    G = sib.scalar_mul(sib.COFACTOR, sib.G_FULL)
    _tag_int, _counter, _pre, H, _trace = sib.derive_h(constants, mds)
    out("g_u", fe(G[0]))
    out("g_v", fe(G[1]))
    out("g_encode", encode(G).hex())
    out("h_u", fe(H[0]))
    out("h_v", fe(H[1]))
    out("h_encode", encode(H).hex())
    check("check_spec_g", G == (SPEC_PIN["g_u"], SPEC_PIN["g_v"])
          and encode(G).hex() == SPEC_PIN["g_encoding"])
    check("check_spec_h", H == (SPEC_PIN["h_u"], SPEC_PIN["h_v"])
          and encode(H).hex() == SPEC_PIN["h_encoding"])
    check("check_g_h_in_subgroup", in_prime_subgroup(G) and in_prime_subgroup(H))
    c42 = sibling_numeric_commit(42, 12345, G, H)
    check("check_spec_sibling_c_42_12345",
          c42 == (SPEC_PIN["c_42_12345_u"], SPEC_PIN["c_42_12345_v"])
          and encode(c42).hex() == SPEC_PIN["c_42_12345_encoding"])
    c42_ext = to_affine(ext_add(ext_mul(42, to_ext(G)), ext_mul(12345, to_ext(H))))
    check("check_ext_arith_c_42_12345_matches_sibling", c42_ext == c42)

    # ---------------- B. positive fixtures ----------------
    results = {}
    for name, B, recipe in payloads():
        r = hash_bytes_to_scalar(B)
        results[name] = (B, r)
        out("%s_n" % name, r["n"])
        if recipe is None:
            out("%s_payload" % name, B.hex())
        else:
            out("%s_recipe" % name, recipe)
        out("%s_b0" % name, r["b0"].hex())
        out("%s_b1" % name, r["b1"].hex())
        out("%s_b2" % name, r["b2"].hex())
        out("%s_uniform" % name, r["u"].hex())
        out("%s_s" % name, fe(r["s"]))
        if not (len(r["u"]) == 48 and 0 <= r["s"] < L_ORDER
                and r["u"] == r["b1"] + r["b2"][:16]
                and r["s"] == hash_bytes_to_scalar_octet_form(B)):
            failures.append("internal_%s" % name)
            out("check_internal_%s" % name, "false")
    check("check_octet_form_matches_all", not any(f.startswith("internal_") for f in failures))
    stream_ok = True
    for name in ("empty", "utf8_text", "all_bytes", "pattern_8193", "pattern_65536"):
        B, r = results[name]
        for chunk in (1, 7, 64, 4096):
            if name.startswith("pattern_65536") and chunk == 1:
                continue
            stream_ok &= hash_bytes_to_scalar_streaming(B, chunk) == r["s"]
    check("check_streaming_chunks_match", stream_ok)
    # b0's input is n + 122 octets; SHA-256 pads within a block while length mod 64 <= 55.
    boundary = {5: 63, 6: 0, 7: 1, 55: 49, 56: 50, 60: 54, 61: 55, 62: 56, 63: 57, 64: 58,
                125: 55, 126: 56}
    check("check_padding_boundary_lengths",
          all((n + 122) % 64 == m and "pattern_%d" % n in results for n, m in boundary.items()))
    check("check_nfc_nfd_differ", results["nfc_e"][1]["s"] != results["nfd_e"][1]["s"])
    check("check_empty_zero1_differ", results["empty"][1]["s"] != results["zero1"][1]["s"])
    check("check_lead_trail_zero_differ",
          results["lead_zero"][1]["s"] != results["trail_zero"][1]["s"])
    check("check_empty_equals_pattern_0", results["empty"][1] == results["pattern_0"][1])
    all_s = [r["s"] for _n, (_B, r) in results.items() if _n != "pattern_0"]
    check("check_all_s_distinct", len(set(all_s)) == len(all_s))
    try:
        hash_bytes_to_scalar(_FakeLen(MAX_PAYLOAD_BYTES + 1))
        check("check_rejects_n_above_max", False)
    except InputRejected:
        check("check_rejects_n_above_max", True)

    # ---------------- C. commitments ----------------
    r2 = R2_RAW
    out("r1", fe(R1))
    out("r2", fe(R2_RAW))
    check("check_r2_lt_l", R2_RAW < L_ORDER)
    if r2 >= L_ORDER:
        r2 %= L_ORDER
        out("r2_reduced", fe(r2))
    commit_ok = True
    subgroup_ok = True
    for name in ("empty", "zero1", "utf8_text", "all_bytes", "pattern_8193"):
        B, rs = results[name]
        for tag, r in (("r1", R1), ("r2", r2)):
            C = c_bytes(B, r, G, H)
            out("%s_c_%s_u" % (name, tag), fe(C[0]))
            out("%s_c_%s_v" % (name, tag), fe(C[1]))
            out("%s_c_%s_encode" % (name, tag), encode(C).hex())
            commit_ok &= C == sibling_numeric_commit(rs["s"], r, G, H)
            subgroup_ok &= on_curve(C) and in_prime_subgroup(C)
            dec, _why = receive(encode(C))
            commit_ok &= dec == C
    C0 = c_bytes(b"", 0, G, H)
    out("empty_c_r0_u", fe(C0[0]))
    out("empty_c_r0_v", fe(C0[1]))
    out("empty_c_r0_encode", encode(C0).hex())
    commit_ok &= C0 == sibling_numeric_commit(results["empty"][1]["s"], 0, G, H)
    check("check_c_bytes_equals_sibling_numeric_c", commit_ok)
    check("check_commitments_in_subgroup_and_roundtrip", subgroup_ok)
    check("check_empty_c_r0_not_identity", C0 != (0, 1))
    check("check_empty_c_r0_equals_s_g", C0 == to_affine(ext_mul(results["empty"][1]["s"],
                                                                 to_ext(G))))
    for key, bad_r in (("r_eq_l", L_ORDER), ("r_negative", -1)):
        try:
            c_bytes(b"", bad_r, G, H)
            check("check_c_bytes_rejects_%s" % key, False)
        except InputRejected:
            check("check_c_bytes_rejects_%s" % key, True)

    # ---------------- spec section 10 inline known answers ----------------
    e = results["empty"][1]
    check("check_spec10_empty_n", e["n"] == SPEC10["empty_n"])
    check("check_spec10_empty_b0", e["b0"].hex() == SPEC10["empty_b0"])
    check("check_spec10_empty_uniform", e["u"].hex() == SPEC10["empty_uniform"])
    check("check_spec10_empty_s", e["s"] == SPEC10["empty_s"])
    check("check_spec10_zero1_s", results["zero1"][1]["s"] == SPEC10["zero1_s"])
    check("check_spec10_utf8_text_s", results["utf8_text"][1]["s"] == SPEC10["utf8_text_s"])
    check("check_spec10_empty_c_r0_encode", encode(C0).hex() == SPEC10["empty_c_r0_encode"])
    check("check_spec10_empty_c_r1_encode",
          encode(c_bytes(b"", R1, G, H)).hex() == SPEC10["empty_c_r1_encode"])
    check("check_spec10_utf8_text_c_r1_encode",
          encode(c_bytes(results["utf8_text"][0], R1, G, H)).hex()
          == SPEC10["utf8_text_c_r1_encode"])

    # ---------------- D. mutations on utf8_text ----------------
    B, rs = results["utf8_text"]
    true_s = rs["s"]
    out("mut_payload", "utf8_text")
    out("mut_true_s", fe(true_s))
    for name, fn in MUTATIONS:
        ms = fn(B)
        out("mut_%s_s" % name, fe(ms))
        if name != "signed":
            check("check_mut_%s_differs" % name, ms != true_s)
    # The two's-complement reading equals the unsigned one whenever the top bit of u is clear,
    # which is the case for utf8_text (u[0] < 0x80). It is therefore checked on that payload as
    # "equal", and shown to differ on the first fixture payload whose u has the top bit set.
    top_clear = rs["u"][0] < 0x80
    out("mut_signed_utf8_text_u_top_bit_set", tf(not top_clear))
    check("check_mut_signed_equal_on_utf8_text", top_clear and mut_signed(B) == true_s)
    alt = next(n for n, (_b, r) in results.items() if r["u"][0] >= 0x80)
    alt_B, alt_r = results[alt]
    alt_ms = mut_signed(alt_B)
    out("mut_signed_alt_payload", alt)
    out("mut_signed_alt_true_s", fe(alt_r["s"]))
    out("mut_signed_alt_s", fe(alt_ms))
    check("check_mut_signed_differs_on_alt", alt_ms != alt_r["s"])
    check("check_mut_signed_differs_iff_top_bit_set_all_fixtures",
          all((mut_signed(b) != r["s"]) == (r["u"][0] >= 0x80) for b, r in results.values()))

    # ---------------- E. negative decoding fixtures ----------------
    t2 = (0, P - 1)
    i_root = fsqrt(P - 1)
    t4 = (i_root if i_root % 2 == 0 else P - i_root, 0)
    t4_odd = (P - t4[0], 0)  # the other order-4 point, odd u, sign bit set
    mixed = to_affine(ext_add(to_ext(G), to_ext(t2)))
    check("check_t2_on_curve_order_2", on_curve(t2) and small_order(t2) == 2)
    check("check_t4_on_curve_order_4", on_curve(t4) and small_order(t4) == 4
          and on_curve(t4_odd) and small_order(t4_odd) == 4 and t4_odd[0] % 2 == 1)
    check("check_mixed_on_curve_not_small_order",
          on_curve(mixed) and small_order(mixed) is None
          and ext_is_identity(ext_mul(2 * L_ORDER, to_ext(mixed))))
    # Order-8 points: [2](u, v) has v = 0 iff v^2 + u^2 = 0 (a = -1 doubling formula), i.e.
    # u^2 = -v^2. Substituting into -u^2 + v^2 = 1 + d u^2 v^2 gives d v^4 + 2 v^2 - 1 = 0, so
    # v^2 = (-1 +/- sqrt(1 + d)) / d. Take the first root for which v^2 is a square; choose
    # v = min(v, p - v) and the even u (canonical choice for this fixture).
    t8 = None
    sq1d = fsqrt(1 + D)
    for sgn in (1, -1):
        v2 = (-1 + sgn * sq1d) * finv(D) % P
        if sq1d is not None and legendre_is_square(v2) and legendre_is_square(P - v2):
            v8 = fsqrt(v2)
            v8 = min(v8, P - v8)
            u8 = fsqrt(P - v2)
            u8 = u8 if u8 % 2 == 0 else P - u8
            t8 = (u8, v8)
            break
    g_plus_t8 = to_affine(ext_add(to_ext(G), to_ext(t8)))
    lg_full = sib.scalar_mul(sib.L, sib.G_FULL)  # torsion component of G_full, via the sibling
    t8_multiples = set()
    acc = EXT_IDENTITY
    for _k in range(8):
        acc = ext_add(acc, to_ext(lg_full))
        t8_multiples.add(to_affine(acc))
    check("check_t8_on_curve_order_8", t8 is not None and on_curve(t8) and small_order(t8) == 8
          and to_affine(ext_mul(2, to_ext(t8)))[1] == 0)
    check("check_t8_in_torsion_of_g_full", small_order(lg_full) == 8 and t8 in t8_multiples)
    check("check_g_plus_t8_order_8l",
          on_curve(g_plus_t8) and small_order(g_plus_t8) is None
          and ext_is_identity(ext_mul(8 * L_ORDER, to_ext(g_plus_t8)))
          and not ext_is_identity(ext_mul(4 * L_ORDER, to_ext(g_plus_t8))))
    out("neg_small_order_8_u", fe(t8[0]))
    out("neg_small_order_8_v", fe(t8[1]))
    out("neg_mixed_order_8_u", fe(g_plus_t8[0]))
    out("neg_mixed_order_8_v", fe(g_plus_t8[1]))
    off_v = 2
    while True:
        vv = off_v * off_v % P
        if not legendre_is_square((vv - 1) * finv(D * vv + 1)):
            break
        off_v += 1
    out("neg_off_curve_v", off_v)
    out("neg_small_order_4_u", fe(t4[0]))
    out("neg_mixed_order_u", fe(mixed[0]))
    out("neg_mixed_order_v", fe(mixed[1]))
    out("neg_wrong_length_note", "lengths other than 32 are rejected by rule 1; not emitted")
    max_cleared = b"\xff" * 31 + b"\x7f"
    identity_alias = bytearray(encode((0, 1)))
    identity_alias[31] |= 0x80
    negs = [
        ("v_ge_p", P.to_bytes(32, "little")),
        ("v_ge_p_max", max_cleared),
        ("identity_sign_alias", bytes(identity_alias)),
        ("off_curve", off_v.to_bytes(32, "little")),
        ("small_order_2", encode(t2)),
        ("small_order_4", encode(t4)),
        ("small_order_4_odd", encode(t4_odd)),
        ("mixed_order", encode(mixed)),
        ("v_ge_p_alias_identity", (P + 1).to_bytes(32, "little")),
        ("small_order_8", encode(t8)),
        ("mixed_order_8", encode(g_plus_t8)),
    ]
    check("check_v_ge_p_max_is_ge_p", int.from_bytes(max_cleared, "little") >= P)
    for name, data in negs:
        out("neg_%s_input" % name, data.hex())
        out("neg_%s_expected" % name, "reject")
        pt, why = receive(data)
        out("neg_%s_reason" % name, why)
        check("check_neg_%s_rejected" % name, pt is None and len(data) == 32)
    for name, n in (("31", 31), ("33", 33), ("0", 0)):
        check("check_neg_length_%s_rejected" % name, receive(bytes(n))[0] is None)
    alias = (P + 1).to_bytes(32, "little")
    check("check_neg_v_ge_p_alias_identity_matches_expected",
          alias.hex() == EXPECTED_V_GE_P_ALIAS_IDENTITY and alias[31] & 0x80 == 0)
    check("check_neg_v_ge_p_alias_identity_reason_v_ge_p", receive(alias)[1] == "v_ge_p")
    reduced_pt, _why = receive_with_v_reduced_mod_p(alias)
    check("check_neg_v_ge_p_alias_identity_reduced_would_accept", reduced_pt == (0, 1))
    pos_id = encode((0, 1))
    out("pos_identity_input", pos_id.hex())
    out("pos_identity_expected", "accept")
    pt, _why = receive(pos_id)
    check("check_pos_identity_accepted", pt == (0, 1))

    return finish(1 if failures else 0)


class _FakeLen(bytes):
    """A bytes object that reports a huge length, to test the MAX_PAYLOAD_BYTES gate without
    allocating it. The gate must fire before any octet is hashed."""

    def __new__(cls, n):
        obj = super().__new__(cls, b"")
        obj._n = n
        return obj

    def __len__(self):
        return self._n


if __name__ == "__main__":
    sys.exit(main())
