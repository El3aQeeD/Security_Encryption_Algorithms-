#!/usr/bin/env python
# coding: utf-8

# In[88]:


import numpy as np


# In[89]:


def not_repeated_letters(text):
    not_repeated = ""
    
    for letter in text:
        if letter not in not_repeated:
            not_repeated += letter
    return not_repeated    


# In[90]:


def fill_sorted_alpha(not_repeated):
    for letter in 'abcdefghiklmnopqrstuvwxyz':
        if letter not in not_repeated:
            not_repeated += letter
    return not_repeated


# In[112]:


def create_pairs_of_letters(input_string):

    # Pair up letters
    pairs = [input_string[i:i+2] for i in range(0, len(input_string), 2)]
    # Check for equal pairs, shift the second character to the next pair, and delete it from the current pair
    for pair in range(len(pairs)):
        if len(pairs[pair]) == 2:
            if pairs[pair][0] == pairs[pair][1]:
                new_triple = pairs[pair][0] + "x" + pairs[pair][1]
                pairs.pop(pair)
                pairs.insert(pair, new_triple)
                flattened_string = ''.join([item for sublist in pairs for item in sublist])
                return flattened_string
                
    return False

def get_final_string(string):
    final_string = string
    result = string
    while True:
        result = create_pairs_of_letters(result)
        if result == False:
            break
        final_string = result
    
    if len(final_string) % 2 != 0:
        final_string += 'x'
    return final_string


# In[113]:


def final_letter_pairs(input_string):
    # Pair up letters
    pairs = [input_string[i:i+2] for i in range(0, len(input_string), 2)]
    return pairs


# In[91]:


def create_table(sorted):
    # Convert the string to a NumPy array with shape (5, 5)
    array_5x5 = np.array(list(sorted)).reshape(5, 5)
    return array_5x5


# In[236]:


def get_position_encryption(matrix, letter1, letter2):
    
    # Find the indices of the two letters in the matrix
    indices_letter1 = np.argwhere(matrix == letter1)
    indices_letter2 = np.argwhere(matrix == letter2)
    #print(indices_letter1)
    #print(indices_letter2)
    #print(matrix.shape)
    # Check if the letters are in the same row, column, or intersection
    if np.any(indices_letter1[:, 0] == indices_letter2[:, 0]):
        
        next_column1 = (indices_letter1[0,1] + 1)
        next_column2 = (indices_letter2[0,1] + 1)
        
        if next_column1 > (matrix.shape[1]-1):
            next_column1 = 0
        if next_column2 > (matrix.shape[1]-1):
            next_column2 = 0
            
        #print(matrix[indices_letter1[0,0],next_column1]) 
        #print(matrix[indices_letter2[0,0],next_column2]) 
        letter_one = matrix[indices_letter1[0,0],next_column1]
        letter_two = matrix[indices_letter2[0,0],next_column2]
        
        #print('Same row')
        return letter_one, letter_two
    elif np.any(indices_letter1[:, 1] == indices_letter2[:, 1]):
        
        next_row1 = (indices_letter1[0,0] + 1)
        next_row2 = (indices_letter2[0,0] + 1)

        if next_row1 > (matrix.shape[0]-1):
            next_row1 = 0
        if next_row2 > (matrix.shape[0]-1):
            next_row2 = 0
        
        #print(matrix[next_row1, indices_letter1[0,1]]) 
        #print(matrix[next_row2, indices_letter2[0,1]]) 
        letter_one = matrix[next_row1, indices_letter1[0,1]]
        letter_two = matrix[next_row2, indices_letter2[0,1]]
        #print('Same column')
        return letter_one, letter_two
    else: # A-based row of A and col of I // I-based row of I col of A
        letter_one = matrix[indices_letter1[0,0], indices_letter2[0,1]]
        letter_two = matrix[indices_letter2[0,0], indices_letter1[0,1]]
        #print("Different row and column")
        return letter_one, letter_two


# In[237]:


def get_position_decryption(matrix, letter1, letter2):
    
    # Find the indices of the two letters in the matrix
    indices_letter1 = np.argwhere(matrix == letter1)
    indices_letter2 = np.argwhere(matrix == letter2)
    #print(indices_letter1)
    #print(indices_letter2)
    #print(matrix.shape)
    # Check if the letters are in the same row, column, or intersection
    if np.any(indices_letter1[:, 0] == indices_letter2[:, 0]):
        
        next_column1 = (indices_letter1[0,1] - 1)
        next_column2 = (indices_letter2[0,1] - 1)
        
        if next_column1 < 0:
            next_column1 = (matrix.shape[1]-1)
        if next_column2 < 0:
            next_column2 = (matrix.shape[1]-1)
            
        #print(matrix[indices_letter1[0,0],next_column1]) 
        #print(matrix[indices_letter2[0,0],next_column2]) 
        letter_one = matrix[indices_letter1[0,0],next_column1]
        letter_two = matrix[indices_letter2[0,0],next_column2]
        
        #print('Same row')
        return letter_one, letter_two
    elif np.any(indices_letter1[:, 1] == indices_letter2[:, 1]):
        
        next_row1 = (indices_letter1[0,0] - 1)
        next_row2 = (indices_letter2[0,0] - 1)

        if next_row1 < 0:
            next_row1 = (matrix.shape[0]-1)
        if next_row2 < 0:
            next_row2 = (matrix.shape[0]-1)
        
        #print(matrix[next_row1, indices_letter1[0,1]]) 
        #print(matrix[next_row2, indices_letter2[0,1]]) 
        letter_one = matrix[next_row1, indices_letter1[0,1]]
        letter_two = matrix[next_row2, indices_letter2[0,1]]
        #print('Same column')
        return letter_one, letter_two
    else: # get the intersected letter between the two given letters
        letter_one = matrix[indices_letter1[0,0], indices_letter2[0,1]]
        letter_two = matrix[indices_letter2[0,0], indices_letter1[0,1]]
        #print("Different row and column")
        return letter_one, letter_two


# In[247]:


def encryption_playfair(plain_text, key='qwerty'):
    encryption_list = []
    
    no_spaces_plain_text = plain_text.replace(" ", "")
    lowercase_plain_text = no_spaces_plain_text.lower()

    not_repeated = not_repeated_letters(key)
    #print('not_repeated_key:', not_repeated)
    
    sorted_letters = fill_sorted_alpha(not_repeated)
    #print('sorted_letters:', sorted_letters)
    
    table = create_table(sorted_letters)
    #print('matrix:',table)
    
    plaintext_modified = get_final_string(lowercase_plain_text)
    #print('plaintext_after_modification:', plaintext_modified)
    
    final_plaintext = final_letter_pairs(plaintext_modified)
    #print('final_plaintext_in pairs:', final_plaintext)
    
    for pair in final_plaintext:
        encrypted_pair = get_position_encryption(table, pair[0], pair[1])
        encryption_list.append(encrypted_pair)
    #print('encryption_list:', encryption_list)
    
    flattened_string = ''.join([''.join(t) for t in encryption_list])
    print(flattened_string)
    return flattened_string


# In[248]:


def decryption_playfair(cipher_text, key='qwerty'):
    decryption_list = []
    
    no_spaces_cipher_text = cipher_text.replace(" ", "")
    lowercase_cipher_text = no_spaces_cipher_text.lower()
    
    not_repeated = not_repeated_letters(key)
    #print('not_repeated_key:', not_repeated)
    
    sorted_letters = fill_sorted_alpha(not_repeated)
    #print('sorted_letters:', sorted_letters)
    
    table = create_table(sorted_letters)
    #print('matrix:',table)
    
    cipher_text_modified = get_final_string(lowercase_cipher_text)
    #print('cipher_text_after_modification:', cipher_text_modified)
    
    final_cipher_text = final_letter_pairs(cipher_text_modified)
    #print('final_plaintext_in pairs:', final_cipher_text)
    
    for pair in final_cipher_text:
        decrypted_pair = get_position_decryption(table, pair[0], pair[1])
        decryption_list.append(decrypted_pair)
    #print('decryption_list:', decryption_list)
    flattened_string = ''.join([''.join(t) for t in decryption_list])
    #print(flattened_string)
    return flattened_string
    


# In[255]:


#encryption('Khaled hany haidy hoss','qwerty')


# In[256]:


#decryption('fiymtbgblbgbkcbflxuz', 'qwerty')


# In[ ]:




