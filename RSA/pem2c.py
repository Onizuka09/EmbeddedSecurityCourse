#!/usr/bin/env python3
# Usage: python3 pem2c.py MyPrivKey.pem > rsa_keys.h
#        python3 pem2c.py MyPubKey.pem  > rsa_pub.h
import sys
from cryptography.hazmat.primitives import serialization

def nbytes(x):
    return (x.bit_length() + 7) // 8

def carr(name, x, size=None):
    size = size or nbytes(x)
    b = x.to_bytes(size, "big")          # big-endian, no extra 00 byte
    out = [f"static const uint8_t {name}[{size}] = {{"]
    for i in range(0, size, 16):
        out.append("    " + ", ".join(f"0x{v:02X}" for v in b[i:i+16]) + ",")
    out.append("};")
    return "\n".join(out)

data = open(sys.argv[1], "rb").read()

try:
    key = serialization.load_pem_private_key(data, password=None)
    pn = key.private_numbers()
    pub = pn.public_numbers
    private = True
except (ValueError, TypeError):
    pub = serialization.load_pem_public_key(data).public_numbers()
    private = False

n, e = pub.n, pub.e
key_len = nbytes(n)                       # 256 for RSA-2048

print("#include <stdint.h>\n")
print(f"#define RSA_LEN {key_len}\n")
print(carr("rsa_n", n, key_len))
print()
print(carr("rsa_e", e))                   # 65537 -> 3 bytes: 01 00 01

if private:
    half = key_len // 2
    print()
    print(carr("rsa_d", pn.d, key_len))
    print("\n/* CRT parameters (optional, for faster decryption) */")
    print(carr("rsa_p",    pn.p, half))
    print(carr("rsa_q",    pn.q, half))
    print(carr("rsa_dp",   pn.dmp1, half))
    print(carr("rsa_dq",   pn.dmq1, half))
    print(carr("rsa_qinv", pn.iqmp, half))
