from cryptography.hazmat.primitives.asymmetric import ec
d = int("9F8745C1B9C1A4039FC7DA34E46F4A50B536CF59B68416C6050B2FD671E525D9", 16)
n = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers()
print(f"{n.x:064X}\n{n.y:064X}")   # must equal Qx and Qy from the MCU
