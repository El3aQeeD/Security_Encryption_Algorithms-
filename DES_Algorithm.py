#!/usr/bin/env python
# coding: utf-8

# In[89]:


plain_text = "Khaled and hany IS the best"
key= "qwerty"
import numpy as np

def split_plaintext_to_blocks(plain_text):
    blocks = []
    letters = []
    for index in range(len(plain_text)):
        if index % 8 == 0 and index != 0:
            blocks.append(letters)
            letters = []
        letters.append(plain_text[index])

    # Handle the last block
    if len(letters) != 0:
        for _ in range(8 - len(letters)):
            letters.append(0)
        blocks.append(letters)

    return blocks




# In[90]:


def convert_to_binary(block):
    binary=[]
    for l in block:
        if isinstance(l, (str)):
            if l == "~":
                res = format(int(0),'08b')
            else:
                res = ''.join(format(ord(l), '08b'))
            binary.append(res)
        elif isinstance(l, (int, float)):
            # Convert numerical values to binary
            binary.append(format(int(l),'08b'))
    return binary


# In[91]:


initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]
perm_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

perm_2 = [14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32]
exp_perm = [32, 1, 2, 3, 4, 5, 4, 5,
        6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1]
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

per = [16,  7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25]

shift_table = [1, 1, 2, 2,
               2, 2, 2, 2,
               1, 2, 2, 2,
               2, 2, 2, 1]

inverse_perm = [40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25]


# In[92]:


def perm(vector,perm):
    result_perm_list = []
    for index in range(len(perm)):
        result_perm_list.append(vector[perm[index]-1])
    return result_perm_list


# In[93]:


def create_binary_block(block):
    binary_block=[]
    for b in block:
        for l in b:
            binary_block.append(l)
    return binary_block


# In[94]:


from collections import deque

def left_circular_shift(input_list, shift_amount):
    shifted_list_l=[]
    deque_list=[]
    deque_list = deque(input_list)
    deque_list.rotate(-shift_amount)
    shifted_list_l = list(deque_list)
    # print('shifted')
    # print(shifted_list)
    return shifted_list_l




# In[95]:


def XOR(block1,block2):
    result_block=[]
    for index in range(len(block1)):
        if block1[index]==block2[index]:
            result_block.append('0')
        else:
            result_block.append('1')
    return result_block


# In[96]:


def decimal_to_binary(decimal_number, num_bits=4):
    # Convert decimal to binary
    binary_representation = bin(decimal_number)[2:]

    # Calculate the number of bits needed for padding
    padding = max(0, num_bits - len(binary_representation))

    # Pad with leading zeros if necessary
    binary_representation_padded = '0' * padding + binary_representation

    return binary_representation_padded


# In[97]:


def Sbox_fucntion(block):
    
    sbox_result = []
    count = 0
    i = 0
    
    for i in range(0,len(block),i+6):
        if i % len(block) <  (len(block) - 5):
            row = block[i] + block[i+5]
            row = int(row,2)
            col = ''
            for k in range(i+1,i+5):
                col += block[k]
            col = int(col, 2)
            
            decimal_value = sbox[count][row][col]
            binary_value = decimal_to_binary(decimal_value)
            sbox_result += [value for value in binary_value]
            count += 1
    return sbox_result


# In[98]:


def convert_block_to_text(block):
    string=""
    count=0
    for num in block:
        count+=1
        string+=num
        if count%8==0:
            string+=" "
    # print(string)
    return string



key_64 = None
key_56 = None

def encrypt_des(plain_text,key="qwerty"):
    global key_64
    global key_56
    cipherText=[]
    result = split_plaintext_to_blocks(plain_text)
    result_key=(split_plaintext_to_blocks(key))
    key_64=(create_binary_block(convert_to_binary(result_key[0])))
    key_56=perm(key_64,perm_1)
    for block in result:
        shifted_key=[]
        final_result=[]
        block_64=(create_binary_block(convert_to_binary(block)))
        IP_block=perm(block_64,initial_perm)
        
        left_key_28=key_56[:int(len(key_56)/2)]
        right_key_28=key_56[int(len(key_56)/2):]
        for round in range(0,16):
            
            left_key_28=(left_circular_shift(left_key_28,shift_table[round]))
            
            right_key_28=(left_circular_shift(right_key_28,shift_table[round]))
            
            shifted_key=left_key_28+right_key_28

            key_48=perm(shifted_key,perm_2)

            Ep=perm(IP_block[int(len(IP_block)/2):],exp_perm)
            XOR_key=XOR(key_48,Ep)
            after_sbox = Sbox_fucntion(XOR_key)
            block_32=perm(after_sbox,per)
            
            XOR_block_32=XOR(block_32,IP_block[:int(len(IP_block)/2)])
            if round<15:
                final_result=IP_block[int(len(IP_block)/2):]+XOR_block_32
            else:
                final_result=XOR_block_32 + IP_block[int(len(IP_block)/2):]
                IP_INV_block=(perm(final_result,inverse_perm))
                cipherText.append(IP_INV_block)

            IP_block=final_result
            final_result=[]
            shifted_key=[]

    print('cipher:',len(cipherText[0]))
    print('key56:', key_56)
    s=""
    print(f"e{cipherText}")
    for index in range(len(cipherText)):
        for index2 in range(len(cipherText[index])):
            s+=cipherText[index][index2]
        s+=","

    return s



# In[120]:


def decrypt_des(IP_INV_block,key="qwerty"):
    IP_INV_block2=[]
    s=""
    l=[]
    l2=[]
    print("------------------------------------------")
    for index in range(len(IP_INV_block)):
        if IP_INV_block[index]==",":
            l2.append(l)
            l=[]
            continue
        l.append(IP_INV_block[index])
    if l2==[] or l!=[]:
        l2.append(l)
    IP_INV_block=l2
    result_key=(split_plaintext_to_blocks(key))
    key_64=(create_binary_block(convert_to_binary(result_key[0])))
    key_56=perm(key_64,perm_1)
    
    for block in IP_INV_block:
        shifted_key=[]
        final_result=[]
        IP_block=perm(block,initial_perm)
        left_key_28=key_56[:int(len(key_56)/2)]
        right_key_28=key_56[int(len(key_56)/2):]
        for round in range(15,-1,-1):
            v = shift_table[:round+1]
            v = np.array(v)
            left_key_28_2=(left_circular_shift(left_key_28,v.sum()))
            
            right_key_28_2=(left_circular_shift(right_key_28,v.sum()))
            
            shifted_key=left_key_28_2+right_key_28_2

            key_48=perm(shifted_key,perm_2)

            Ep=perm(IP_block[int(len(IP_block)/2):],exp_perm)
            XOR_key=XOR(key_48,Ep)
            after_sbox = Sbox_fucntion(XOR_key)
            block_32=perm(after_sbox,per)
            
            XOR_block_32=XOR(block_32,IP_block[:int(len(IP_block)/2)])
            if round>0:
                final_result=IP_block[int(len(IP_block)/2):]+XOR_block_32
            else:
                final_result=XOR_block_32 + IP_block[int(len(IP_block)/2):]
                final_perm=perm(final_result,inverse_perm)
                IP_INV_block2.append(final_perm)
                s+=str(convert_block_to_text(final_perm))
            IP_block=final_result
            final_result=[]
            shifted_key=[]
    string_value = ''.join([chr(int(binary, 2)) for binary in s.split()])
    return string_value
        


# In[125]:
""" messages= encrypt_des('hi am khaled') """


# print("String:", decrypt_des(encrypt_des(plain_text,key)))


# In[ ]:




