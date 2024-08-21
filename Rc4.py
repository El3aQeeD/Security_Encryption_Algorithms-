import json
def generate_T(key):
    T = [0] * 256
    key_len = len(key)

    for i in range(256):
        T[i] = ord(key[i % key_len])

    return T


def initialize_state(key):
    S = list(range(256))
    T = generate_T(key)
    k_len = len(T)

    j = 0
    for i in range(256):
        j = (j + S[i] + T[i % k_len]) % 256
        S[i], S[j] = S[j], S[i]

    return S

def generate_keystream(S, length):
    i, j = 0, 0
    keystream = []

    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        keystream.append(S[t])

    return keystream


def rc4_encrypt(data):
    S = initialize_state(key)
    # print(f"data:{type(data)}")
    if isinstance(data, str):
        data=bytes(data, encoding='utf-8')
    keystream = generate_keystream(S, len(data))

    result = [byte ^ keystream[i] for i, byte in enumerate(data)]
    ciphertext_str = json.dumps(result)
    return ciphertext_str

def rc4_decrypt(data):
    data = json.loads(data)
    # print(f"daee:{(bytes(data))}")
    return bytes(json.loads(rc4_encrypt(bytes(data)))).decode()


plaintext = b"Hello, We will travel tommorow be ready!"
key = "qwerty"

# Encryption
# encrypted_data = rc4_encrypt(plaintext)
# print("Encrypted:", encrypted_data)

# # Decryption
# decrypted_data = rc4_decrypt(encrypted_data)
# print("Decrypted:", decrypted_data)

# T = generate_T(key)
# S = initialize_state(key)
# print("Temporary Vector T:", T)
# print("Length of T:", len(T))
# print("Length of S:", S)
