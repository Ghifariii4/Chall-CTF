import hashlib
import json
from datetime import datetime, timezone
from Crypto.Cipher import ChaCha20

# Pure Python implementation of Rust's rand 0.8 StdRng (ChaCha12Rng)
def pcg32_seed_from_u64(state: int) -> bytes:
    seed = bytearray()
    for _ in range(8):
        state = (state * 6364136223846793005 + 1) & 0xFFFFFFFFFFFFFFFF
        xorshift = (((state >> 18) ^ state) & 0xFFFFFFFFFFFFFFFF) >> 27
        rot = (state >> 59) & 31
        res = ((xorshift >> rot) | (xorshift << ((32 - rot) & 31))) & 0xFFFFFFFF
        seed.extend(res.to_bytes(4, 'little'))
    return bytes(seed)

def chacha_quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = ((x[d] ^ x[a]) << 16 | (x[d] ^ x[a]) >> 16) & 0xFFFFFFFF
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = ((x[b] ^ x[c]) << 12 | (x[b] ^ x[c]) >> 20) & 0xFFFFFFFF
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = ((x[d] ^ x[a]) << 8  | (x[d] ^ x[a]) >> 24) & 0xFFFFFFFF
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = ((x[b] ^ x[c]) << 7  | (x[b] ^ x[c]) >> 25) & 0xFFFFFFFF

def chacha12_block(key_bytes, stream_id=0, nonce=0):
    state = [0x61707865, 0x3320746e, 0x79622d32, 0x6b206574]
    key_words = [int.from_bytes(key_bytes[i:i+4], 'little') for i in range(0, 32, 4)]
    state.extend(key_words)
    state.append(stream_id & 0xFFFFFFFF)
    state.append((stream_id >> 32) & 0xFFFFFFFF)
    state.append(nonce & 0xFFFFFFFF)
    state.append((nonce >> 32) & 0xFFFFFFFF)
    
    x = list(state)
    for _ in range(6):
        chacha_quarter_round(x, 0, 4, 8, 12)
        chacha_quarter_round(x, 1, 5, 9, 13)
        chacha_quarter_round(x, 2, 6, 10, 14)
        chacha_quarter_round(x, 3, 7, 11, 15)
        chacha_quarter_round(x, 0, 5, 10, 15)
        chacha_quarter_round(x, 1, 6, 11, 12)
        chacha_quarter_round(x, 2, 7, 8, 13)
        chacha_quarter_round(x, 3, 4, 9, 14)
    
    out = bytearray()
    for i in range(16):
        out.extend(((x[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, 'little'))
    return bytes(out)

def generate_key_rust_stdrng(seed_u64: int) -> bytes:
    key_seed = pcg32_seed_from_u64(seed_u64)
    block = chacha12_block(key_seed)
    return block[:32]

class CustomCrc32:
    def __init__(self, polynomial, initial_value, final_xor, reflect_input, reflect_output):
        self.polynomial = polynomial & 0xFFFFFFFF
        self.initial_value = initial_value & 0xFFFFFFFF
        self.final_xor = final_xor & 0xFFFFFFFF
        self.reflect_input = reflect_input
        self.reflect_output = reflect_output
        self.table = self._generate_table()
    
    def _generate_table(self):
        table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ self.polynomial
                else:
                    crc >>= 1
                crc &= 0xFFFFFFFF
            table.append(crc)
        return table
    
    def _reflect_byte(self, byte):
        result = 0
        for i in range(8):
            if byte & (1 << i):
                result |= 1 << (7 - i)
        return result
    
    def _reflect_u32(self, value):
        result = 0
        for i in range(32):
            if value & (1 << i):
                result |= 1 << (31 - i)
        return result & 0xFFFFFFFF
    
    def checksum(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        crc = self.initial_value
        for byte in data:
            input_byte = self._reflect_byte(byte) if self.reflect_input else byte
            table_index = (crc ^ input_byte) & 0xFF
            crc = ((crc >> 8) ^ self.table[table_index]) & 0xFFFFFFFF
        final_crc = self._reflect_u32(crc) if self.reflect_output else crc
        return (final_crc ^ self.final_xor) & 0xFFFFFFFF
    
    def checksum_two_strings(self, str1, ident, str2):
        concatenated = f"{str1}_{ident}_{str2}"
        return self.checksum(concatenated)

    @classmethod
    def custom_polynomial(cls, polynomial):
        return cls(polynomial, 0xFFFFFFFF, 0xFFFFFFFF, True, True)

BASE64_ALPHABET = "KdauhQCHrjc9GyWAYgoU72x8kzVRlZ3BSN14vsieIptX6JTDPmEq5FOL0nMwfb+/"

def base64_encode(data: bytes, alphabet: str = BASE64_ALPHABET) -> str:
    result = []
    for i in range(0, len(data), 3):
        chunk = data[i:i+3]
        val = 0
        for b in chunk:
            val = (val << 8) | b
        val <<= (8 * (3 - len(chunk)))
        
        c1 = alphabet[(val >> 18) & 0x3F]
        c2 = alphabet[(val >> 12) & 0x3F]
        c3 = alphabet[(val >> 6) & 0x3F] if len(chunk) > 1 else '='
        c4 = alphabet[val & 0x3F] if len(chunk) > 2 else '='
        result.extend([c1, c2, c3, c4])
        
    return ''.join(result)

def build_challenge_data(flag: str, seed: int, hostname: str, os_name: str, username: str, repo_name: str):
    flag_bytes = flag.encode('utf-8')
    key = generate_key_rust_stdrng(seed)
    nonce = hashlib.md5(hostname.encode('utf-8')).digest()[:12]
    
    cipher = ChaCha20.new(key=key, nonce=nonce)
    enc_bytes = bytearray(cipher.encrypt(flag_bytes))
    
    custom_crc = CustomCrc32.custom_polynomial(0xdeadb33f)
    for i in range(len(enc_bytes)):
        crc32_out = custom_crc.checksum_two_strings(username, i + 0xcbc, repo_name)
        enc_bytes[i] ^= (crc32_out & 0xff)
    
    ciphertext_b64 = base64_encode(bytes(enc_bytes))
    
    comment_body = f"hostname: {hostname}, os: {os_name}, username: {username}, ciphertext: {ciphertext_b64}"
    return comment_body, ciphertext_b64, seed

if __name__ == "__main__":
    FLAG = "TDCTF{sh0uld_i_bl0ck_g1thub_b3c4us3_1t_1s_u5ed_by_m4lw4re?}"
    HOSTNAME = "MALWARE-PC"
    OS_NAME = "Windows 10 Pro"
    USERNAME = "victim_user"
    REPO_NAME = "s3cr3t_b4db10c"
    
    # Example timestamp seed (ms)
    NOW_TIMESTAMP_MS = int(datetime.now(timezone.utc).timestamp()) * 1000
    
    comment_body, ct_b64, seed = build_challenge_data(FLAG, NOW_TIMESTAMP_MS, HOSTNAME, OS_NAME, USERNAME, REPO_NAME)
    
    print("=== GENERATED CTF CHALLENGE PAYLOAD ===")
    print(f"Flag: {FLAG}")
    print(f"Seed (ms): {seed}")
    print(f"Comment Body:\n{comment_body}\n")
