#!/usr/bin/env python3
# Usage:
#   python3 verify_ecdsa.py --qx <hex> --qy <hex> --r <hex> --s <hex> --msg "Hello World!"
#   python3 verify_ecdsa.py ... --file message.bin
#   python3 verify_ecdsa.py ... --hash <sha256 hex>      (if you only have the hash)
import argparse, hashlib, sys
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def h2i(s):
    s = s.strip().replace(" ", "").replace(":", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    return int(s, 16)

Qx="E8E6BD3FB624943781ADDAAB62FD68913FD7F948A47333A4A588002BBFE3A082"
Qy="8E0EAF6038596B12048262C25A1ADCCD0893E6B926968FCA1FAF1BD11CFA6150"
S="8F8F21EED8EBC246B0BCE171C1247F69B2FC21C0C4CD2CF8C78A01879A8CA850"
R="B2B2552A4B102D020E0C40D645E2F0E12C4E48273CC8047134ACE1478E6CE75F"
message="Hello World!"
#
# ap = argparse.ArgumentParser()
# ap.add_argument("--qx", required=True)
# ap.add_argument("--qy", required=True)
# ap.add_argument("--r",  required=True)
# ap.add_argument("--s",  required=True)
# g = ap.add_mutually_exclusive_group(required=True)
# g.add_argument("--msg",  help="message as text")
# g.add_argument("--file", help="message from a file")
# g.add_argument("--hash", help="SHA-256 of the message, in hex")
# a = ap.parse_args()

pub = ec.EllipticCurvePublicNumbers(h2i(Qx), h2i(Qy), ec.SECP256R1())
try:
    pub = pub.public_key()            # also checks that Q is on the curve
except ValueError:
    sys.exit("Q is not a valid point on P-256: check Qx/Qy")

sig = utils.encode_dss_signature(h2i(R), h2i(S))

try:
    data = message.encode() # to bytes
    print("SHA-256:", hashlib.sha256(data).hexdigest().upper())
    pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
    print("SIGNATURE VALID")
except InvalidSignature:
    print("SIGNATURE INVALID")
    sys.exit(1)
