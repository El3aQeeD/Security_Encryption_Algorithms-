#!/usr/bin/env python
# coding: utf-8

# In[12]:


def caesar_cipher_encrypt(plaintext, shift=3):
    encrypted_text = ""

    for char in plaintext:
        if char.isalpha():
            # Determine whether the character is uppercase or lowercase
            is_upper = char.isupper()

            # Apply the Caesar Cipher shift
            char_code = ord(char)
            shifted_code = (char_code - ord('A' if is_upper else 'a') + shift) % 26
            encrypted_char = chr(shifted_code + ord('A' if is_upper else 'a'))

            encrypted_text += encrypted_char
        else:
            # Keep non-alphabetic characters unchanged
            encrypted_text += char

    return encrypted_text

def caesar_cipher_decrypt(ciphertext, shift=3):
    # Decryption is the same as encryption, but with a negative shift
    return caesar_cipher_encrypt(ciphertext, -shift)

""" # Example usage
plaintext = "EL HARB htbd2 el sa3a 10 p.m"
shift_amount = 50

# Encrypt the plaintext
encrypted_text = caesar_cipher_encrypt(plaintext, shift_amount)
print(f"Encrypted Text: {encrypted_text}")

# Decrypt the ciphertext
decrypted_text = caesar_cipher_decrypt(encrypted_text, shift_amount)
print(f"Decrypted Text: {decrypted_text}") """

