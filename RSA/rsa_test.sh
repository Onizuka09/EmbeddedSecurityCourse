# 1. Build a 256-byte block: 244 zero bytes + "Hello World!" (12 bytes)
head -c 244 /dev/zero > m.bin
printf 'Hello World!' >> m.bin

# 2. Check the size and content
wc -c m.bin                 # must print 256
xxd m.bin | tail -n 2       # the end should show: 48656c6c6f20576f726c6421
xxd -r -p m.bin
# 3. Raw RSA encryption with the public key
openssl pkeyutl -encrypt -pubin -inkey MyPubKey.pem \
    -pkeyopt rsa_padding_mode:none -in m.bin -out secret.enc

# 4. Show the ciphertext as hex (compare with the MCU "Cipher RSA" output)
xxd -p secret.enc | tr -d '\n' | tr 'a-f' 'A-F'; echo
