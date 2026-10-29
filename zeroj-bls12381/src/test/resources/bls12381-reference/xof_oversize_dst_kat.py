# Independent RFC 9380 expand_message_xof (SHAKE256) with the section 5.3.3 oversize-DST reduction,
# k = 128 -> ceil(2k/8) = 32-byte reduced DST. Standard library only.
import hashlib
def xof(msg, dst, n):
    if len(dst) > 255:
        dst = hashlib.shake_256(b"H2C-OVERSIZE-DST-" + dst).digest(32)
    dst_prime = dst + bytes([len(dst)])
    return hashlib.shake_256(msg + n.to_bytes(2, "big") + dst_prime).digest(n)
dst = bytes((7 * i + 3) & 0xff for i in range(296))
print("dst-rule: byte i = (7*i + 3) mod 256, 296 bytes")
print("msg=abc len=80", xof(b"abc", dst, 80).hex())
print("msg=empty len=80", xof(b"", dst, 80).hex())
# sanity: 255-byte DST is NOT reduced, so it must differ from reducing it
print("255-byte dst unreduced", xof(b"abc", dst[:255], 32).hex())
