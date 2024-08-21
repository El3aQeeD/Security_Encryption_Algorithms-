import secrets
import json

# Global Public Elements
q = 144680345296684229304575179529938245101116505796297724604093354959605529698553710091437622563823349977233953598919282328617313556530076978689781274705883651331885037231666129678790666583467909689725051848798939477054509622827204488057693951443317602316042032987991969996748116892536606440843751763423931593  # A large prime number
a = 3  # a < q and a is a primitive root of q

def Key_Generation_by_Alice(q, a):
    Xa = secrets.randbelow(q - 1) + 1  # select private Xa "private key"
    Ya = pow(a, Xa, q)  # Calculate Ya "Public key"
    return Ya, Xa  # Public key, Private key

# Encryption by Bob with Alice's Public key
def encrypt_gamal(q, a, public_key, message): 
    Ya = public_key
    M = [ord(char) for char in message]  # Convert each character to its ASCII value
    k = secrets.randbelow(q - 1) + 1  # select random integer k
    
    Ciphertext = []
    for i in range(len(M)):
        k = secrets.randbelow(q - 1) + 1  # select random integer k
        K = pow(Ya, k, q)  # Calculate K
        C1 = pow(a, k, q)  # Calculate C1
        C2 = (K * M[i]) % q  # Calculate C2
        Ciphertext.append([C1, C2])  # Add the ciphertext pair for each character
    return Ciphertext   # Ciphertext

# Decryption by Alice with Alice's Private key
def decrypt_gamal(q, private_key, ciphertext):
    Xa = private_key
    
    DecryptedText = ""
    for i in range(len(ciphertext)):
        C1, C2 = ciphertext[i]
        K = pow(C1, Xa, q)  # Calculate K
        K_inverse = pow(K, -1, q)
        M = (C2 * K_inverse) % q
        DecryptedText += chr(M)  # Convert ASCII value back to a character and append to the decrypted text
    
    return DecryptedText  # Decrypted text

""" # Key Generation for Alice
public_key_Alice, private_key_Alice = Key_Generation_by_Alice(q, a)

# Key Generation for Bob (using the same q and a)
#public_key_Bob, private_key_Bob = Key_Generation_by_Alice(q, a)

# Bob encrypts a message for Alice
message_text = "k"  # replace with your message
ciphertext = encrypt_gamal(q, a, public_key_Alice, message_text)

# Alice decrypts the message from Bob
decrypted_message = decrypt_gamal(q, private_key_Alice, ciphertext)


#print(type(public_key_Alice))
#print(type(private_key_Alice))


#print("okkkkkk")

print(f"Original Message: {message_text}")
#print(type(message_text))
print(f"Ciphertext: {ciphertext}")
#print(type(ciphertext))
print(f"Decrypted Message: {decrypted_message}")
#print(type(decrypted_message))

# Convert list of lists to a string
#ciphertext_str = json.dumps(ciphertext)
#Print the type
#print(type(ciphertext_str))

# Print the string representation
#print("List of Lists as String:")
#print(ciphertext_str)


# Convert the string back to the original list of lists
#retrieved_list_of_lists = json.loads(ciphertext_str)

#Print the type
#print(type(retrieved_list_of_lists))

# Print the retrieved list of lists
#print("Retrieved List of Lists:")
#print(retrieved_list_of_lists)



 """