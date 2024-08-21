def msg_and_key(msg ,key):

    msg = msg.upper()
    key = key.upper()


    key_map = ""

    j=0
    for i in range(len(msg)):
        if ord(msg[i]) == 32:
            # ignoring space
            key_map += " "
        else:
            if j < len(key):
                key_map += key[j]
                j += 1
            else:
                j = 0
                key_map += key[j]
                j += 1

    #print(key_map)
    return msg, key_map


def create_vigenere_table():
    table = []
    for i in range(26):
        table.append([])

    for row in range(26):
        for column in range(26):
            if (row + 65) + column > 90:
                table[row].append(chr((row+65) + column - 26))
            else:
                
                table[row].append(chr((row+65)+column))

    #print(table)
    return table


def vigenere_cipher_encryption(message):
    message, mapped_key = msg_and_key(message, key = "qwerty")
    table = create_vigenere_table()
    encrypted_text = ""

    for i in range(len(message)):
        if message[i] == chr(32):
            encrypted_text += " "
        else:
            row = ord(message[i])-65
            column = ord(mapped_key[i]) - 65
            encrypted_text += table[row][column]

    return encrypted_text         

    print("Encrypted Message: {}".format(encrypted_text))


def itr_count(mapped_key, message):
    counter = 0
    result = ""

   
    for i in range(26):
        if mapped_key + i > 90:
            result += chr(mapped_key+(i-26))
        else:
            result += chr(mapped_key+i)

    
    for i in range(len(result)):
        if result[i] == chr(message):
            break
        else:
            counter += 1

    return counter


def vigenere_cipher_decryption(message):

    message, mapped_key = msg_and_key(message, key = "qwerty")
    table = create_vigenere_table()
    decrypted_text = ""

    for i in range(len(message)):
        if message[i] == chr(32):
            decrypted_text += " "
        else:
            decrypted_text += chr(65 + itr_count(ord(mapped_key[i]), ord(message[i])))

    return decrypted_text         

    print("Decrypted Message: {}".format(decrypted_text))


print(vigenere_cipher_encryption("hello my name is hoss"))
print(vigenere_cipher_decryption(vigenere_cipher_encryption("hello my name is hoss")))

'''
def main():
    choice = int(input("1. Encryption\n2. Decryption\nChoose(1,2): "))
    if choice == 1:
        print("---Encryption is activated---")
        message, mapped_key = msg_and_key()
        cipher_encryption(message, mapped_key)

    elif choice == 2:
        print("---Decryption is activated---")
        message, mapped_key = msg_and_key()
        cipher_decryption(message, mapped_key)

    else:
        print("Unknown")


if __name__ == "__main__":
    main()

'''
