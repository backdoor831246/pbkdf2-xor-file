# pbkdf2-xor-file
source_file.txt
  → 
[UTF-8 Text Read]
  → 
[Text → Numeric Encoding (ord(c):03)]
  → 
[Luhn checksum appended (integrity verification)]
  → 
[PBKDF2-HMAC-SHA256 key derivation]
    - input: generated password
    - salt: os.urandom(16)
    - iterations: 100,000
  → 
[Vernam Cipher (XOR encryption)]
  → 
encrypted_file.enc
    - binary output
    - unreadable content

Also include a separate section showing PASSWORD GENERATION:

User Input:
- Service Name
- Nickname
- Login
- Secret Phrase

→ 
[Seed concatenation]
→ 
[Seed hardening (length + constant)]
→ 
[MD5-based deterministic PRNG]
→ 
[Strong password generation]

And a DECRYPTION FLOW:

encrypted_file.enc
  → 
[Extract salt]
  → 
[PBKDF2 key regeneration]
  → 
[XOR decryption]
  → 
[Luhn verification]
    - if failed → "Wrong password or corrupted file"
  → 
[Numeric decoding → original UTF-8 text]
  → 
restored_file.txt
- Clear arrows
- Short technical labels
- No emojis
- No explanations outside the diagram
