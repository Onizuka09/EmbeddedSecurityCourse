#!/usr/bin/env python3
# Usage: python3 ecc2c.py [curve] > ecc_params.h      (default: prime256v1)
import subprocess, re, sys

curve = sys.argv[1] if len(sys.argv) > 1 else "prime256v1"
txt = subprocess.check_output(
    ["openssl", "ecparam", "-name", curve, "-param_enc", "explicit",
     "-text", "-noout"], text=True)

# Collect each section: "Name:" followed by indented hex lines
sec, cur = {}, None
for line in txt.splitlines():
    if line.startswith(" "):
        if cur is not None:
            sec[cur] += line.strip().replace(":", "")
    else:
        m = re.match(r"^([^:]+):\s*$", line)
        cur = m.group(1) if m else None
        if m:
            sec[cur] = ""

p = int(sec["Prime"], 16)
a = int(sec["A"], 16)
b = int(sec["B"], 16)
n = int(sec["Order"], 16)
g = sec["Generator (uncompressed)"]
assert g.startswith("04")
gx, gy = int(g[2:2 + len(g[2:]) // 2], 16), int(g[2 + len(g[2:]) // 2:], 16)

size = (p.bit_length() + 7) // 8             # 32 for P-256
a_abs = p - a if a > p // 2 else a           # a = p-3  ->  |a| = 3
a_neg = a > p // 2

def carr(name, x):
    bts = x.to_bytes(size, "big")
    out = [f"static const uint8_t {name}[{size}] = {{"]
    for i in range(0, size, 16):
        out.append("    " + ", ".join(f"0x{v:02X}" for v in bts[i:i+16]) + ",")
    out.append("};")
    return "\n".join(out)

print("#include <stdint.h>\n")
print(f"#define EC_LEN {size}")
print(f"#define EC_COEF_SIGN {0 if not a_neg else 1}  /* 1 = a is negative */\n")
print(carr("P256_p", p));      print()
print(carr("P256_a_abs", a_abs)); print()
print(carr("P256_b", b));      print()
print(carr("P256_n", n));      print()
print(carr("P256_Gx", gx));    print()
print(carr("P256_Gy", gy))
