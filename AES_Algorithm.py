#!/usr/bin/env python
# coding: utf-8

# In[62]:


plain_text = "Khaled, hossam, haidy, and hany IS the best"
key= "qwertyfotddyohpjdadadafafafafaff"


def split_plaintext_to_blocks(plain_text):
    blocks = []
    letters = []
    for index in range(len(plain_text)):
        if index % 16 == 0 and index != 0:
            blocks.append(letters)
            letters = []
        letters.append(plain_text[index])

    # Handle the last block
    if len(letters) != 0:
        for _ in range(16 - len(letters)):
            letters.append(["00"])
        blocks.append(letters)

    return blocks


# In[63]:


def convert_to_hex(blocks):
    hexa=[]
    list_hexa=[]
    for block in blocks:
        for l in block:
            if isinstance(l, (str)):
                if l == "~":
                    res = format(int(0),'08b')
                else:
                    res = ''.join([hex(ord(char))[2:] for char in l])
                hexa.append(res)
            elif isinstance(l, (int, float)):
                hexa.append(00)
                # binary.append(0)
        list_hexa.append(hexa)
        hexa=[]
    return list_hexa


# In[64]:


def RotWord(word,repetation,direction):
    for rep in range(repetation):
        if direction==1:
            for index in range(1,len(word)):
                temp=word[index]
                word[index]=word[index-1]
                word[index-1]=temp
        elif direction==2:
            for index in reversed(range(0,len(word)-1)):
                temp=word[index]
                word[index]=word[index+1]
                word[index+1]=temp
    return word


# In[65]:


def SubWord(word,s_box):
    new_word=[]
    for index in range(len(word)):
        new_word.append([s_box[int(word[index][0], 16)]])
    return new_word


# In[66]:


def XOR(block1,block2):
    result_block=""
    for index in range(len(block1)):
        if block1[index]==block2[index]:
            result_block+='0'
        else:
            result_block+='1'
    return result_block


# In[67]:


def Rcon(word,rcon_index):
    resulted_word=[]
    for index in range(len(word)):
        if index==0:
            hex_result = hex(int(XOR(format(int(word[index][0], 16), '08b'),format(int(rcon_table[rcon_index+1], 16), '08b')), 2))[2:]
        else:
            hex_result = hex(int(XOR(format(int(word[index][0], 16), '08b'),format(int("0", 16), '08b')), 2))[2:]
        resulted_word.append([hex_result])
    return resulted_word


# In[68]:


def full_word_XOR(word1,word2):
    hex_result=[]
    shex=[]
    for index in range(len(word1)):
        shex.append(hex(int(XOR(format(int(word1[index][0], 16), '08b'),format(int(word2[index][0], 16), '08b')), 2))[2:])
        hex_result.append(shex)
        shex=[]
    return hex_result


# In[69]:


s_box = [
    "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76",
    "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0",
    "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15",
    "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75",
    "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84",
    "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF",
    "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8",
    "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2",
    "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73",
    "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB",
    "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79",
    "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08",
    "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A",
    "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E",
    "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF",
    "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"
]

rcon_table = [
    "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F"
]


inverse_sbox = [
    '52', '09', '6a', 'd5', '30', '36', 'a5', '38', 'bf', '40', 'a3', '9e', '81', 'f3', 'd7', 'fb',
    '7c', 'e3', '39', '82', '9b', '2f', 'ff', '87', '34', '8e', '43', '44', 'c4', 'de', 'e9', 'cb',
    '54', '7b', '94', '32', 'a6', 'c2', '23', '3d', 'ee', '4c', '95', '0b', '42', 'fa', 'c3', '4e',
    '08', '2e', 'a1', '66', '28', 'd9', '24', 'b2', '76', '5b', 'a2', '49', '6d', '8b', 'd1', '25',
    '72', 'f8', 'f6', '64', '86', '68', '98', '16', 'd4', 'a4', '5c', 'cc', '5d', '65', 'b6', '92',
    '6c', '70', '48', '50', 'fd', 'ed', 'b9', 'da', '5e', '15', '46', '57', 'a7', '8d', '9d', '84',
    '90', 'd8', 'ab', '00', '8c', 'bc', 'd3', '0a', 'f7', 'e4', '58', '05', 'b8', 'b3', '45', '06',
    'd0', '2c', '1e', '8f', 'ca', '3f', '0f', '02', 'c1', 'af', 'bd', '03', '01', '13', '8a', '6b',
    '3a', '91', '11', '41', '4f', '67', 'dc', 'ea', '97', 'f2', 'cf', 'ce', 'f0', 'b4', 'e6', '73',
    '96', 'ac', '74', '22', 'e7', 'ad', '35', '85', 'e2', 'f9', '37', 'e8', '1c', '75', 'df', '6e',
    '47', 'f1', '1a', '71', '1d', '29', 'c5', '89', '6f', 'b7', '62', '0e', 'aa', '18', 'be', '1b',
    'fc', '56', '3e', '4b', 'c6', 'd2', '79', '20', '9a', 'db', 'c0', 'fe', '78', 'cd', '5a', 'f4',
    '1f', 'dd', 'a8', '33', '88', '07', 'c7', '31', 'b1', '12', '10', '59', '27', '80', 'ec', '5f',
    '60', '51', '7f', 'a9', '19', 'b5', '4a', '0d', '2d', 'e5', '7a', '9f', '93', 'c9', '9c', 'ef',
    'a0', 'e0', '3b', '4d', 'ae', '2a', 'f5', 'b0', 'c8', 'eb', 'bb', '3c', '83', '53', '99', '61',
    '17', '2b', '04', '7e', 'ba', '77', 'd6', '26', 'e1', '69', '14', '63', '55', '21', '0c', '7d'
]

mix_columns_table = [
    ['02', '03', '01', '01'],
    ['01', '02', '03', '01'],
    ['01', '01', '02', '03'],
    ['03', '01', '01', '02']
]
inv_mix_columns_matrix = [
        ['0E', '0B', '0D', '09'],
        ['09', '0E', '0B', '0D'],
        ['0D', '09', '0E', '0B'],
        ['0B', '0D', '09', '0E']
    ]


# In[70]:


def generate_subkey(Ikey):
    subkeys=[]
    word1=[]
    if len(subkeys)<2:
        print("you must generate first two subkeys")
        key_hex=convert_to_hex(Ikey)
        subkeys=[split_plaintext_to_blocks(key_hex)[0],split_plaintext_to_blocks(key_hex)[1]]
    for index in range(2,15):
        key=[]
        rot=RotWord(subkeys[index-1][12:16],1,1)
        sub=SubWord(rot,s_box)
        rcon=Rcon(sub,index-2)
        word1=full_word_XOR(rcon,subkeys[index-1][0:4])
        word2=full_word_XOR(word1,subkeys[index-1][4:8])
        word3=full_word_XOR(word2,subkeys[index-1][8:12])
        word4=full_word_XOR(word3,subkeys[index-1][12:16])
        skey=word1+word2+word3+word4
        subkeys.append(skey)
    return subkeys


# In[71]:


def shift_rows(block):
    w0=[block[0]]+[block[4]]+[block[8]]+[block[12]]
    w1=[block[1]]+[block[5]]+[block[9]]+[block[13]]
    w2=[block[2]]+[block[6]]+[block[10]]+[block[14]]
    w3=[block[3]]+[block[7]]+[block[11]]+[block[15]]
    w1=RotWord(w1,1,1)
    w2=RotWord(w2,2,1)
    w3=RotWord(w3,3,1)
    block=[w0[0]]+[w1[0]]+[w2[0]]+[w3[0]]+[w0[1]]+[w1[1]]+[w2[1]]+[w3[1]]+[w0[2]]+[w1[2]]+[w2[2]]+[w3[2]]+[w0[3]]+[w1[3]]+[w2[3]]+[w3[3]]
    return block
    


# In[72]:


def inverse_shift_rows(block):
    w0=[block[0]]+[block[4]]+[block[8]]+[block[12]]
    w1=[block[1]]+[block[5]]+[block[9]]+[block[13]]
    w2=[block[2]]+[block[6]]+[block[10]]+[block[14]]
    w3=[block[3]]+[block[7]]+[block[11]]+[block[15]]
    w1=RotWord(w1,1,2)
    w2=RotWord(w2,2,2)
    w3=RotWord(w3,3,2)
    block=[w0[0]]+[w1[0]]+[w2[0]]+[w3[0]]+[w0[1]]+[w1[1]]+[w2[1]]+[w3[1]]+[w0[2]]+[w1[2]]+[w2[2]]+[w3[2]]+[w0[3]]+[w1[3]]+[w2[3]]+[w3[3]]
    return block
    


# In[73]:


def gf_multiply(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B  # GF(2^8) modulus
        b >>= 1
    return result


# In[74]:


def inverse_mix_columns(state):
    result = [[0 for _ in range(4)] for _ in range(4)]

    for col in range(4):
        for row in range(4):
            result[row][col] = (
                gf_multiply(int(inv_mix_columns_matrix[row][0], 16), int(state[col][0], 16)) ^
                gf_multiply(int(inv_mix_columns_matrix[row][1], 16), int(state[col][1], 16)) ^
                gf_multiply(int(inv_mix_columns_matrix[row][2], 16), int(state[col][2], 16)) ^
                gf_multiply(int(inv_mix_columns_matrix[row][3], 16), int(state[col][3], 16))
            )

    return result





# In[75]:


def mix_columns(state,mix_columns_matrix):
    # MixColumns matrix

    a=[]
    b=[]
    for i in range(1,17):
        a.append(state[i-1][0])
        if i%4==0:
            b.append(a)
            a=[]
    state=b


    result = [[0 for _ in range(4)] for _ in range(4)]

    for col in range(4):
        for row in range(4):
            result[col][row] = (
                gf_multiply(int(mix_columns_matrix[row][0], 16), int(state[col][0], 16)) ^
                gf_multiply(int(mix_columns_matrix[row][1], 16), int(state[col][1], 16)) ^
                gf_multiply(int(mix_columns_matrix[row][2], 16), int(state[col][2], 16)) ^
                gf_multiply(int(mix_columns_matrix[row][3], 16), int(state[col][3], 16))
            )
    mixed=[]
    for row in range(len(result)):
        for col in range(len(result[row])):
            m=[hex(result[row][col])[2:]]
            mixed.append(m)

    return mixed


# In[ ]:





# In[76]:


def AES_encrypt(plain_text):
    subkeys=generate_subkey(key)
    blocks_plaintext_hex=convert_to_hex(plain_text)
    # blocks_plaintext_hex=[["01"],["23"],["45"],["67"],["89"],["ab"],["cd"],["ef"],["fe"],["dc"],["ba"],["98"],["76"],["54"],["32"],["10"]]
    blocks_plaintext = split_plaintext_to_blocks(blocks_plaintext_hex)
    cipher_text=[]
    for block in blocks_plaintext:
        next_round_key=full_word_XOR(block,subkeys[0])
        # print(f"round_key{subkeys[0]}")
        for index in range(14):
            round_key=next_round_key
            sub=SubWord(round_key,s_box)
            # print(f"subt::{sub}")
            shiftted=shift_rows(sub)
            # print(f"shiftted::{shiftted}")
            if index<13:
                mix=mix_columns(shiftted,mix_columns_matrix=mix_columns_table)
                # print(f"mix::{mix}")
                next_round_key=full_word_XOR(mix,subkeys[index+1])
            else:
                cipher_text.append(full_word_XOR(shiftted,subkeys[index+1]))
        #     print(f"round_key{subkeys[index+1]}")
        # print(f"cipher {index+2}: {cipher_text}")
    c=""
    for block2 in cipher_text:
        for index in range(len(block2)):
            if len(block2[index][0])==1:
                c+="0" 
            c+=block2[index][0]
    # print(cipher_text)
    return c


# In[77]:


def AES_decrypt(cipher_text):
    plain=[]
    segments = [cipher_text[i:i+32] for i in range(0, len(cipher_text), 32)]

    # Split each 32-character segment into individual 2-letter elements
    result_list = [list([segment[i:i+2]] for i in range(0, len(segment), 2)) for segment in segments]

    # print(result_list)
    cipher_text=result_list
    subkeys=generate_subkey(key)
    for block in cipher_text:
        # print(block)
        next_round_key=full_word_XOR(block,subkeys[len(subkeys)-1])
        # print(f"key{subkeys[len(subkeys)-1]}")
        # print(f"round_key{next_round_key}")
        for index in range(14):
            round_key=next_round_key
            shiftted=inverse_shift_rows(round_key)
            # print(f"shiftted::{shiftted}")
            sub=SubWord(shiftted,inverse_sbox)
            # print(f"subt::{sub}")
            next_round_key=full_word_XOR(sub,subkeys[len(subkeys)-index-1-1])
            if index<13:
                mix=mix_columns(next_round_key,inv_mix_columns_matrix)
                # print(f"mix::{mix}")
                next_round_key=mix
            if index==13:
                plain.append(next_round_key)

            # print(f"round_key{subkeys[len(subkeys)-index-1-1]}")
            # print(f"start {index+2}: {next_round_key}")
            # print(subkeys[index+1])
        # print(f'plain:{plain}')
        # print(f'result2:{block}')
    ascii_result = ''

    for sublist in plain:
        for hex_value in sublist:
            for pair in hex_value:
                ascii_result += chr(int(pair, 16))

    # print(ascii_result)
    return ascii_result


# In[78]:


def Aes(plain_text):
    cipher_text=AES_encrypt(plain_text)
    plain=AES_decrypt(cipher_text=cipher_text)

    ascii_result = ''

    for sublist in plain:
        for hex_value in sublist:
            for pair in hex_value:
                ascii_result += chr(int(pair, 16))

    print(ascii_result)


# In[79]:


# Aes(plain_text)


# In[ ]:





# In[ ]:




