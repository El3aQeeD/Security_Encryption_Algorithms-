import random
import math




# this is the old code 
def is_prime (number):
    if number < 2:
        return False
    for i in range (2, number // 2 +1):
        if number % i == 0:
            return False
    return True

def Generate_prime (min_value, max_value):
    prime = random.randint (min_value, max_value)
    while not is_prime(prime):
        prime = random.randint(min_value, max_value)
    return prime


def mod_inverse(e, phi):
    for d in range (3, phi):
        if (d * e) % phi == 1:
            return d 
    raise ValueError ("Mod_inverse does not exist!")

""" p, q = Generate_prime(1000, 50000), Generate_prime ( 1000, 50000)
while p==q:
    q= Generate_prime(1000, 50000)

n = p * q
phi_n = (p-1) * (q-1)

e = random.randint (3, phi_n-1)
while math.gcd(e, phi_n) != 1: 
    e = random.randint (3, phi_n - 1)

d = mod_inverse(e, phi_n)  """

def encryption_RSA(message):
    
    p, q = Generate_prime(1000, 50000), Generate_prime ( 1000, 50000)
    
    while p==q:
        q= Generate_prime(1000, 50000)

    n = p * q
    phi_n = (p-1) * (q-1)

    e = random.randint (3, phi_n-1)
    while math.gcd(e, phi_n) != 1: 
        e = random.randint (3, phi_n - 1)

    d = mod_inverse(e, phi_n)
    
    message_encoded = [ord(ch) for ch in message]

    print ("Message after encryption: ", message_encoded)


    ciphertext = [pow(ch, e, n) for ch in message_encoded]

    print (message," Ciphered in: ", ciphertext)
    return ciphertext, n, d



def decryption_RSA(ciphertext,n,d):
    Decodemsg = [pow(ch, d, n) for ch in ciphertext] 
    print ("back to ASCII: ", Decodemsg)
    msg = "".join (chr(ch) for ch in Decodemsg)
    print("from ASCII to original TEXT: ", msg)
    
    return msg

""" ciphertext, n, d = encryption_RSA('Khaled is the best')

# Convert the list to a string with ',' as the separator
values_string = ', '.join(str(value) for value in ciphertext)

print('string:',values_string)

# Split the string into a list of strings using ',' as the separator
values_list = values_string.split(', ')

# Convert the list of strings to a list of integers
integer_list = [int(value) for value in values_list]

print('integer',integer_list)

plain_txet = decryption_RSA(integer_list) """
#message = input("Enter your message to Encrypt ")


""" print ("Prime number P: ", p)
print ("Prime number q: ", q)
print ("Public Key: ", e)
print ("Private Key: ", d)
print ("n: ", n)
print ("Phi of n: ", phi_n, " Secret") """




""" message_encoded = [ord(ch) for ch in message]

print ("Message after encryption: ", message_encoded)


ciphertext = [pow(ch, e, n) for ch in message_encoded]

print (message," Ciphered in: ", ciphertext)

Decodemsg= [pow(ch, d, n) for ch in ciphertext] 
print ("back to ASCII: ", Decodemsg)
msg = "".join (chr(ch) for ch in Decodemsg)
print("from ASCII to original TEXT: ", msg) """

# Database user A user B
# user : ID - Name - public_Key
# chat : ID - ID_user - ID_user
# messages : ID - ID_user - message

#GUI -> user A write message -> encryption -> database -> 
#GUI -> database -> user B recived message -> decryption -> plaintext

