import hashlib, os, base64, string
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
def append_luhn(text: str) -> str:
    check = luhn_checksum(text + "0")
    return text + str((10 - check) % 10)
def verify_luhn(text: str) -> bool:
    return luhn_checksum(text) == 0
def generate_key(password: str, salt: bytes, key_len=32) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000, dklen=key_len)
def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
class PasswordGenerator:
    def __init__(self, seed: str):
        self._seed = seed.encode('utf-8')
    def _next_random_byte(self) -> int:
        h = hashlib.md5(self._seed).digest()
        self._seed = base64.b64encode(h)
        return h[0]
    def generate_password(self, length=16, include_symbols=True) -> str:
        chars = string.ascii_letters + string.digits
        if include_symbols:
            chars += "!@#$%^&*()<>.,=;:{}[]_"
        password = ""
        for _ in range(length):
            index = self._next_random_byte() % len(chars)
            password += chars[index]
        return password
def encrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'r', encoding='utf-8') as f:
        text = f.read()
    text_with_luhn = append_luhn(''.join(f"{ord(c):03}" for c in text))
    salt = os.urandom(16)
    key = generate_key(password, salt)
    encrypted_data = xor_encrypt_decrypt(text_with_luhn.encode(), key)
    with open(output_file, 'wb') as f:
        f.write(salt + encrypted_data)
    print(f"File encrypted: {output_file}")
def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        file_data = f.read()
    salt = file_data[:16]
    encrypted_data = file_data[16:]
    key = generate_key(password, salt)
    decrypted_bytes = xor_encrypt_decrypt(encrypted_data, key)
    decrypted_text = decrypted_bytes.decode()
    if not verify_luhn(decrypted_text):
        raise ValueError("File is corrupted or password is incorrect")
    text_chars = [chr(int(decrypted_text[i:i+3])) for i in range(0, len(decrypted_text)-1, 3)]
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(''.join(text_chars))
    print(f"File decrypted: {output_file}")
if __name__ == "__main__":
    print("Password generator and file encryptor")
    service_name = input("Name Service: ").strip()
    nickname = input("Nickname: ").strip()
    login = input("Login: ").strip()
    secret_phrase = input("Secret phrase: ").strip()
    if not service_name or not login or not secret_phrase:
        print("Error: all fields except nickname are required!")
        exit(1)
    seed = service_name + nickname + login + secret_phrase
    seed += f"{len(seed):x}_NO_MORE_THAN_ILLUSION" # dosX seed algorihm
    generator = PasswordGenerator(seed)
    password = generator.generate_password(20)
    print(f"Generated password: {password}")
    file_to_encrypt = input("File for encryption: ").strip()
    encrypt_file(file_to_encrypt, file_to_encrypt + ".enc", password)
    # decrypt_file(file_to_encrypt + ".enc", "output", password)
