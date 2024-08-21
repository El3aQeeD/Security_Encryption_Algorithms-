#!/usr/bin/env python
# coding: utf-8

# In[78]:


def Row_encrypt(plaintext, key= [4, 3, 1, 2, 5, 6, 7]):
    # Calculate the number of rows needed
    rows = len(plaintext) // len(key)
    if len(plaintext) % len(key) != 0:
        rows += 1
    

    # Create an empty matrix to store the plaintext
    matrix = [[' ' for _ in range(len(key))] for _ in range(rows)]
    
    # Fill in the matrix with the plaintext
    index = 0
    for i in range(rows):
        for j in range(len(key)):
            if index < len(plaintext):
                matrix[i][j] = plaintext[index]
                index += 1
            else:
                matrix[i][j] = "z"
                    
    print(matrix)
    # Perform encryption column by column
    ciphertext = ''
    for col in range(len(key)):
        for row in matrix:
            ciphertext += row[key.index(col + 1)]

    return ciphertext

def Row_decrypt(ciphertext, key= [4, 3, 1, 2, 5, 6, 7]):
    # Calculate the number of rows needed
    rows = len(ciphertext) // len(key)
    if len(ciphertext) % len(key) != 0:
        rows += 1

    # Create an empty matrix to store the ciphertext
    matrix = [[' ' for _ in range(len(key))] for _ in range(rows)]

    # Fill in the matrix with the ciphertext
    index = 0
    for col in range(len(key)):
        for row in range(rows):
            matrix[row][key.index(col + 1)] = ciphertext[index]
            index += 1
            
    print(matrix)
    
    # Extract the plaintext from the matrix
    decryptedtext = ''
    for row in matrix:
        for char in row:
            if char != 'z':
                decryptedtext += char

    return decryptedtext

'''
# Example usage
plaintext = "el harb htbd2 el sa3a 10:00 p.m"
key = [4, 3, 1, 2, 5, 6, 7]

ciphertext = Row_encrypt(plaintext.replace(" ", ""), key)
decrypted_text = Row_decrypt(ciphertext, key)
print("Plaintext:", plaintext)
print("Key:", key)
print("Ciphertext:", ciphertext)
print("Decrypted Text:", decrypted_text)
'''
