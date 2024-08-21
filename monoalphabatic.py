import string

alphabet = string.ascii_lowercase  # lowercase letters



def msg_key(msg,key):
   
    msg_list = [char for char in msg if char.isalpha()]  
    key_list = [char for char in key if char.isalpha()]  
    
    return msg_list, key_list

def mono_encryption(message_list, key="qwerty" ,letters = alphabet ):

    message_list, key = msg_key(message_list,key)

    sorted_key = sorted(set(key), key=key.index)
    for letter in letters:
        if letter not in sorted_key:
            sorted_key.append(letter)

    cipher = []
    for letter in message_list:
        index = letters.index(letter)
        new_letter = sorted_key[index]
        cipher.append(new_letter)
    encrypted_message = "".join(cipher)

    return encrypted_message
    print("Encrypted Message:", encrypted_message)
    

def mono_decryption(encrypted_message, key="qwerty", letters = alphabet ):

    sorted_key = sorted(set(key), key=key.index)
    for letter in letters:
        if letter not in sorted_key:
            sorted_key.append(letter)

    decrypted = []
    i = 0
    for letter in encrypted_message:
        if letter.isalpha():
            index = sorted_key.index(letter)
            original_letter = letters[index]
            decrypted.append(original_letter)
        else:
            decrypted.append(' ')
    decrypted_message = "".join(decrypted)
    return decrypted_message
    #print("Decrypted Message:", decrypted_message)



print(mono_encryption("message"))
print(mono_decryption(mono_encryption("message")))

'''def main():
    choice = int(input("1. Encryption\n2. Decryption\nChoose(1,2): "))
    if choice == 1:
        print("---Encryption is activated---")
        message, key = msg_key()
        letters = [chr(i) for i in range(65, 91)]

        sorted_key = sorted(set(key), key=key.index)
        for letter in letters:
            if letter not in sorted_key:
                sorted_key.append(letter)

        mono_encryption(message, sorted_key, letters)

    elif choice == 2:
        print("---Decryption is activated---")
        #message, key = msg_key()
        letters = [chr(i) for i in range(65, 91)]

        sorted_key = sorted(set(key), key=key.index)
        for letter in letters:
            if letter not in sorted_key:
                sorted_key.append(letter)

        mono_decryption(message, sorted_key, letters)

    else:
        print("Unknown")


if __name__ == "__main__":
    main()
'''



