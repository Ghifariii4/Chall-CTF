def xor_encrypt(plaintext, key):
    pt_bytes = plaintext.encode()
    key_bytes = key.encode()
    
    encrypted_bytes = bytearray()
    for i in range(len(pt_bytes)):
        encrypted_byte = pt_bytes[i] ^ key_bytes[i % len(key_bytes)]
        encrypted_bytes.append(encrypted_byte)
        
    return encrypted_bytes.hex()

key = "REDACTED" 
plaintext = "REDACTED_FLAG"

ciphertext = xor_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext}")