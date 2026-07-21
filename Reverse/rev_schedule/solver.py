import requests
from datetime import datetime, timezone
import hashlib
from Crypto.Cipher import ChaCha20

# Pure Python implementation of Rust's rand 0.8 StdRng (ChaCha12Rng) for offline/cross-platform solving
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

def get_key_py(seed: int) -> bytes:
    key_seed = pcg32_seed_from_u64(seed)
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

def base64_decode(encoded_str: str, base64_alphabet: str) -> bytearray:
    padding_count = encoded_str.count('=')
    encoded_str = encoded_str.rstrip('=')
    
    base64_reverse_map = {char: index for index, char in enumerate(base64_alphabet)}
    output = bytearray()

    for i in range(0, len(encoded_str), 4):
        char1 = base64_reverse_map.get(encoded_str[i], 0)
        char2 = base64_reverse_map.get(encoded_str[i + 1], 0)
        char3 = base64_reverse_map.get(encoded_str[i + 2], 0) if i + 2 < len(encoded_str) else 0
        char4 = base64_reverse_map.get(encoded_str[i + 3], 0) if i + 3 < len(encoded_str) else 0

        combined = (char1 << 18) | (char2 << 12) | (char3 << 6) | char4

        output.append((combined >> 16) & 0xFF)
        if i + 2 < len(encoded_str) or padding_count < 2:
            output.append((combined >> 8) & 0xFF)
        if i + 3 < len(encoded_str) or padding_count < 1:
            output.append(combined & 0xFF)

    return output

def solve_challenge(body_str: str, created_at_iso: str, repo_name: str):
    data = body_str.split(", ")
    hostname = data[0].split(": ")[-1]
    os_info = data[1].split(": ")[-1]
    username = data[2].split(": ")[-1]
    ciphertext = data[3].split(": ")[-1]
    
    dt = datetime.strptime(created_at_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    leaked_seed = int(dt.timestamp() - 5) * 10000
    
    base64_alphabet = "KdauhQCHrjc9GyWAYgoU72x8kzVRlZ3BSN14vsieIptX6JTDPmEq5FOL0nMwfb+/"
    ciphertext_raw = base64_decode(ciphertext, base64_alphabet)
    
    custom_crc = CustomCrc32.custom_polynomial(0xdeadb33f)
    for i in range(len(ciphertext_raw)):
        crc32_out = custom_crc.checksum_two_strings(username, i + 0xcbc, repo_name)
        ciphertext_raw[i] = (crc32_out & 0xff) ^ ciphertext_raw[i]

    nonce = hashlib.md5(hostname.encode()).digest()[:12]
    
    print(f"Bruteforcing seeds near {leaked_seed}...")
    for seed in range(leaked_seed, leaked_seed - 20000, -1):
        key = get_key_py(seed)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        pt = cipher.decrypt(ciphertext_raw)
        if b"TDCTF{" in pt:
            print(f"Found Flag: {pt.decode('utf-8', errors='ignore')}")
            return pt.decode('utf-8', errors='ignore')
            
    print("Flag not found in search range.")
    return None

if __name__ == "__main__":
    # Test Solver against locally generated payload
    from generate_challenge import build_challenge_data, BASE64_ALPHABET
    
    FLAG = "TDCTF{sh0uld_i_bl0ck_g1thub_b3c4us3_1t_1s_u5ed_by_m4lw4re?}"
    HOSTNAME = "MALWARE-PC"
    OS_NAME = "Windows 10 Pro"
    USERNAME = "victim_user"
    REPO_NAME = "s3cr3t_b4db10c"
    
    created_at = "2026-07-21T08:30:00Z"
    dt = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    seed = int(dt.timestamp() - 5) * 10000
    
    body, ct_b64, seed_val = build_challenge_data(FLAG, seed, HOSTNAME, OS_NAME, USERNAME, REPO_NAME)
    print("Generated Body:", body)
    
    print("\n--- RUNNING SOLVER ---")
    solve_challenge(body, created_at, REPO_NAME)
