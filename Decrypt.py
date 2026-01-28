import hashlib
def luhn_checksum(text: str) -> int:
    digits = [int(c) for c in text if c.isdigit()]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10
def verify_luhn(text: str) -> bool:
    return luhn_checksum(text) == 0
def generate_key(password: str, salt: bytes, key_len=32) -> bytes:
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100_000,
        dklen=key_len
    )
def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
def decrypt_file(enc_file: str, out_file: str, password: str):
    with open(enc_file, "rb") as f:
        data = f.read()
    salt = data[:16]
    encrypted = data[16:]
    key = generate_key(password, salt)
    decrypted = xor_encrypt_decrypt(encrypted, key).decode()
    if not verify_luhn(decrypted):
        raise ValueError("Wrong password or corrupted file")
    text = "".join(
        chr(int(decrypted[i:i+3]))
        for i in range(0, len(decrypted) - 1, 3)
    )
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(text)
if __name__ == "__main__":
    enc_file = input("Encrypted file (.enc): ").strip()
    out_file = input("Output file: ").strip()
    password = input("Enter generated password: ").strip()
    try:
        decrypt_file(enc_file, out_file, password)
        print(" Decryption successful")
    except Exception as e:
        print(" ERROR:", e)
