#!/usr/bin/env python
# coding: utf-8

# In[14]:


import tkinter as tk
from tkinter import scrolledtext, END
from datetime import datetime
from PIL import Image, ImageTk, ImageDraw
from PlayFair import *
from database import *
from DES_Algorithm import *
from AES_Algorithm import *
#from El_Gamal_Algorithm import *
from Caesar_Cipher_algorithm import *
from Row_Transposition_Cipher_algorithm import *
from monoalphabatic import *
from vigenere import *
#from Diffie_Helman import *
from socket_server import *
from RSA import *
from Rc4 import *
from El_Gamal_Algorithm import *
#from client_1 import *
import socket
import threading
import pickle

user_id = 1
decrypted_id_client_one = None
decrypted_message_client_one = None
# Define the server address (host, port)
server_address = ('localhost', 12346)

# Create a socket object
client_one_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_one_socket.connect(server_address)



#####
import secrets
import json
# Global Public Elements
q = 144680345296684229304575179529938245101116505796297724604093354959605529698553710091437622563823349977233953598919282328617313556530076978689781274705883651331885037231666129678790666583467909689725051848798939477054509622827204488057693951443317602316042032987991969996748116892536606440843751763423931593  # A large prime number
a = 3 
private_key = None
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

#####
class EncryptionChooser:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Technique Chooser")

        # Set green and white color scheme
        self.root.configure(bg="#25d366")  # Green background

        # Create a label for instructions
        label = tk.Label(root, text="Choose an Encryption Technique:", bg="#25d366", fg="black", font=("Arial", 14))
        label.grid(row=0, column=0, padx=10, pady=10)

        # Create radio buttons for encryption techniques
        self.selected_technique = tk.StringVar()
        techniques = ["DES","AES","RSA","RC4","ELGAMAL","Caesar","Mono","Vigenere","Playfair","Row", "Reil"]  

        for i, technique in enumerate(techniques):
            radio_button = tk.Radiobutton(root, text=technique, variable=self.selected_technique, value=technique, bg="#25d366", fg="black", font=("Arial", 12))
            radio_button.grid(row=i+1, column=0, padx=10, pady=5, sticky='w')

        # Create a button to continue
        continue_button = tk.Button(root, text="Continue", command=self.open_chat_app, bg="#25d366", fg="white", font=("Arial", 12, "bold"))
        continue_button.grid(row=len(techniques) + 1, column=0, padx=10, pady=10)

    def open_chat_app(self):
        selected_technique = self.selected_technique.get()
        print(selected_technique)
        
        # Close the current window
        self.root.destroy()

        # Open the chat app with the selected encryption technique
        if selected_technique != "":
            root = tk.Tk()
            chat_app = WhatsApp(root, selected_technique)

            # connect the database
            connect_db()

            # Get user name from database if it exists
            user_exist = get_user_name_by_id(user_id, 'user')

            if user_exist:
                # Send the client name to the server
                client_one_socket.send(user_exist.encode())

            # Start a thread to receive messages from the server
            receive_thread = threading.Thread(target=chat_app.receive_messages)
            receive_thread.start()
                # connect to database
                
            connect_db()
            
            if selected_technique == 'DES':
                # get messages history from database
                data = get_messages_all_with_user_id('chat_des')
                
                
                for item in data:
                    current_id, current_str= item

                    decrypted_message = decrypt_des(current_str)
                    if user_id == current_id:
                        chat_app.chat_history.insert(tk.END, f"(Khaled): {decrypted_message}\n")
                    else:
                        chat_app.chat_history.insert(tk.END, f"(Hany): {decrypted_message}\n")


            elif selected_technique == "Playfair":
                # get messages history from database
                data = get_messages_all_with_user_id('chat')
                for item in data:
                    current_id, current_str = item                
                    decrypted_message = decryption_playfair(current_str)
                    chat_app.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
                print('Playfair')

            elif selected_technique == "Caesar":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_caesar')
                for item in data:
                    current_id, current_str = item                
                    decrypted_message = caesar_cipher_decrypt(current_str)
                    chat_app.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
                print('Caesar')

            elif selected_technique == "Row":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_row')
                for item in data:
                    current_id, current_str = item                
                    decrypted_message = Row_decrypt(current_str)
                    chat_app.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
                print('Row')

            elif selected_technique == "Mono":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_mono')
                for item in data:
                    current_id, current_str = item                
                    decrypted_message = mono_decryption(current_str)
                    chat_app.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
                print('Mono')

            elif selected_technique == "Vigenere":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_vigenere')
                for item in data:
                    current_id, current_str = item                
                    decrypted_message = vigenere_cipher_decryption(current_str)
                    chat_app.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
                print('Vigenere')


            elif selected_technique == "RSA":   
                #public_key_a,private_key_a = Key_Generation(q,a)
                #chat_app.private_key = private_key_a
                #send_message = "DIFFIE"+','+ str(public_key_a)
                #client_one_socket.send(send_message.encode())

                # get messages history from database
                data = get_messages_all_with_user_id_rsa('chat_rsa')
                
                for item in data:
                    current_id, current_str, n, d = item
                    # Split the string into a list of strings using ',' as the separator
                    values_list = current_str.split(', ')

                    # Convert the list of strings to a list of integers
                    integer_list = [int(value) for value in values_list]   

                    decrypted_message = decryption_RSA(integer_list, n, d)
                    
                    chat_app.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
            elif selected_technique == "AES":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_aes')
                
                
                for item in data:
                    current_id, current_str= item

                    decrypted_message = AES_decrypt(current_str)
                    
                    chat_app.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
            elif selected_technique == "RC4":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_rc4')
                
                
                for item in data:
                    current_id, current_str= item

                    decrypted_message = rc4_decrypt(current_str)
                    
                    chat_app.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")

            elif selected_technique == "ELGAMAL":
                
                # get messages history from database
                data = get_messages_all_with_user_id_gamal('chat_gamal')
                
                for item in data:
                    current_id, current_str, pk = item
                    
                    # Convert the string back to the original list of lists
                    retrieved_list_of_lists = json.loads(current_str)

                    print(retrieved_list_of_lists)

                    decrypted_message = decrypt_gamal(q,int(pk) ,retrieved_list_of_lists)
                    chat_app.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
            
            
            
            root.mainloop()
            print('closed')
            
            
        
class WhatsApp:
    instance = None
    
    def __init__(self, root, selected_technique):
        self.root = root
        self.selected_technique = selected_technique
        self.root.title("WhatsApp - " + selected_technique)
        WhatsApp.instance = self
        self.private_key = private_key
        # Schedule the update_GUI method to be called every 100 milliseconds
        self.root.after(100, self.update_GUI)
        # Set green and white color scheme
        self.root.configure(bg="#25d366")  # Green background

        # Load and resize the profile picture using Pillow
        original_image = Image.open(r"C:\Users\small\Downloads\IMG_7185.jpg")
        resized_image = original_image.resize((50, 50), Image.LANCZOS)  #Lanczos is a filter algorithm that is often used for high-quality image resizing

        # Create a circular mask for the image
        mask = Image.new('L', (50, 50), 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0, 50, 50), fill=255)
        circular_image = Image.new('RGBA', (50, 50), (0, 0, 0, 0))
        circular_image.paste(resized_image, mask=mask)

        # Convert the circular image to PhotoImage
        self.profile_image = ImageTk.PhotoImage(circular_image)

        # Create a Label for the circular image
        self.image_label = tk.Label(root, image=self.profile_image, bg="#25d366")
        self.image_label.grid(row=0, column=0, padx=10, pady=0, sticky='w')  # Align to the left

        # Create a label for the name
        self.name_label = tk.Label(root, text="Khaled", bg="#25d366", fg="black", font=("Arial", 12, "bold"))
        self.name_label.grid(row=1, column=0, padx=10, pady=0, sticky='w')  # Align to the left
        
        # Create labels for video call and voice call symbols
        voice_call_icon = tk.Label(root, text="📞", bg="#25d366", fg="black", font=("Arial", 12))
        voice_call_icon.grid(row=1, column=1, padx=0, pady=0, sticky='e')  # Align to the right

        # Create a Listbox for displaying chat history
        self.chat_history = tk.Listbox(root, selectbackground="lightgreen", selectmode=tk.SINGLE, width=50, height=15, bg="white", fg="black", font=("Arial", 10))
        self.chat_history.grid(row=2, column=0, padx=10, pady=10, columnspan=2)
        
        # Create an entry widget for typing messages
        self.message_entry = tk.Entry(root, width=50, bg="white", fg="black", font=("Arial", 10))
        self.message_entry.grid(row=3, column=0, padx=10, pady=10, columnspan=2)

        # Create a button to send messages
        self.send_button = tk.Button(root, text="Send", command=self.send_message, bg="#25d366", fg="white", font=("Arial", 10, "bold"))
        self.send_button.grid(row=3, column=2, padx=10, pady=10)
    @classmethod
    def  get_instance(cls):
        return cls.instance
    def update_GUI(self):
        print('updated')
        if decrypted_message_client_one is not None:
            connect_db()
            print('inside one')
            self.chat_history.delete(0, END)
            if decrypted_message_client_one == 'DES':
                print('inside two')
                # get messages history from database
                data = get_messages_all_with_user_id('chat_des')
                print('inside three')
                
                for item in data:
                    print('inside four')
                    current_id, current_str= item

                    decrypted_message = decrypt_des(current_str)
                    print('dec',decrypted_message)
                    if user_id == current_id:
                        self.chat_history.insert(tk.END, f"(Khaled): {decrypted_message}\n")
                    else:
                        self.chat_history.insert(tk.END, f"(Hany): {decrypted_message}\n")

            elif decrypted_message_client_one == "Playfair":
                # get messages history from database
                data = get_messages_all_with_user_id('chat')
                for item in data:
                    current_id, current_str = item                
                    decrypted_message = decryption_playfair(current_str)
                    self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
                print('Playfair')

            elif decrypted_message_client_one == "Caesar":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_caesar')
                for item in data:
                    current_id, current_str = item                
                    decrypted_message = caesar_cipher_decrypt(current_str)
                    self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
                print('Caesar')

            elif decrypted_message_client_one == "Row":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_row')
                for item in data:
                    current_id, current_str = item                
                    decrypted_message = Row_decrypt(current_str)
                    self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
                print('Row')

            elif decrypted_message_client_one == "Mono":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_mono')
                for item in data:
                    current_id, current_str = item                
                    decrypted_message = mono_decryption(current_str)
                    self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
                print('Mono')

            elif decrypted_message_client_one == "Vigenere":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_vigenere')
                for item in data:
                    current_id, current_str = item                
                    decrypted_message = vigenere_cipher_decryption(current_str)
                    self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
                print('Vigenere')


            elif decrypted_message_client_one == "RSA":   
                #public_key_a,private_key_a = Key_Generation(q,a)
                #chat_app.private_key = private_key_a
                #send_message = "DIFFIE"+','+ str(public_key_a)
                #client_one_socket.send(send_message.encode())

                # get messages history from database
                data = get_messages_all_with_user_id_rsa('chat_rsa')
                
                for item in data:
                    current_id, current_str, n, d = item
                    # Split the string into a list of strings using ',' as the separator
                    values_list = current_str.split(', ')

                    # Convert the list of strings to a list of integers
                    integer_list = [int(value) for value in values_list]   

                    decrypted_message = decryption_RSA(integer_list, n, d)
                    
                    self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
            elif decrypted_message_client_one == "AES":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_aes')
                
                
                for item in data:
                    current_id, current_str= item

                    decrypted_message = AES_decrypt(current_str)
                    
                    self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
            elif decrypted_message_client_one == "RC4":
                # get messages history from database
                data = get_messages_all_with_user_id('chat_rc4')
                
                
                for item in data:
                    current_id, current_str= item

                    decrypted_message = rc4_decrypt(current_str)
                    
                    self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")

            elif decrypted_message_client_one == "ELGAMAL":
                
                # get messages history from database
                data = get_messages_all_with_user_id_gamal('chat_gamal')
                
                for item in data:
                    current_id, current_str, pk = item
                    
                    # Convert the string back to the original list of lists
                    retrieved_list_of_lists = json.loads(current_str)

                    print(retrieved_list_of_lists)

                    decrypted_message = decrypt_gamal(q,int(pk) ,retrieved_list_of_lists)
                    self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")

        
        
    def send_message(self):
        # Get the message from the entry widget
        message = self.message_entry.get()
        
        # Clear the entry widget
        self.message_entry.delete(0, END)
        
        
        # Encrypt message according to the chosen technique
        if self.selected_technique == "DES":
            print("DES")
            encrypted_message = encrypt_des(message)
            
            send_message = self.selected_technique+','+ encrypted_message+','+str(user_id)
            
            client_one_socket.send(send_message.encode())
            
            user_data = {
                'user_id': user_id,
                'message': encrypted_message,
            }
            print('encrypted_in_main',encrypted_message)
            # insert into database the cipher
            insert_user_data('chat_des', user_data)
            
            # get messages history from database
            data = get_messages_all_with_user_id('chat_des')
            self.chat_history.delete(0, END)
            
            for item in data:
                current_id, current_str= item

                decrypted_message = decrypt_des(current_str)
                if user_id != current_id:
                    self.chat_history.insert(tk.END, f"(Khaled): {decrypted_message}\n")
                else:
                    self.chat_history.insert(tk.END, f"(Hany): {decrypted_message}\n")

        elif self.selected_technique == "AES":
            print("AES")
            encrypted_message = AES_encrypt(message)
            
            send_message = str(self.selected_technique)+','+ encrypted_message+','+str(user_id)
            
            client_one_socket.send(send_message.encode())
            
            user_data = {
                'user_id': user_id,
                'message': encrypted_message,
            }
            print('encrypted_in_main',encrypted_message)
            # insert into database the cipher
            insert_user_data('chat_aes', user_data)
            
            # get messages history from database
            data = get_messages_all_with_user_id('chat_aes')
            self.chat_history.delete(0, END)
            
            for item in data:
                current_id, current_str= item

                decrypted_message = AES_decrypt(current_str)
                
                self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
        elif self.selected_technique == "RSA":
            print("RSA")
            encrypted_text, n, d = encryption_RSA(message)
            
            # Convert the list to a string with ',' as the separator
            values_string = ', '.join(str(value) for value in encrypted_text)
            
            send_message = str(self.selected_technique)+','+ values_string+','+str(user_id)+','+str(n)+','+str(d)
            
            # send to server the data
            client_one_socket.send(send_message.encode())
            
            user_data = {
                'user_id': user_id,
                'message': values_string,
                'n' : n,
                'd':d
            }
            
            print('encrypted_in_main',encrypted_text)
            # insert into database the cipher
            insert_user_data_rsa('chat_rsa', user_data)
            
            # get messages history from database
            data = get_messages_all_with_user_id_rsa('chat_rsa')
            self.chat_history.delete(0, END)
            
            for item in data:
                current_id, current_str, n, d = item
                
                # Split the string into a list of strings using ',' as the separator
                values_list = current_str.split(', ')

                # Convert the list of strings to a list of integers
                integer_list = [int(value) for value in values_list]   

                decrypted_message = decryption_RSA(integer_list, n, d)
                
                self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
            
        elif self.selected_technique == "RC4":
            print("RC4")
            encrypted_message = rc4_encrypt(message)
            
            send_message = str(self.selected_technique)+','+ encrypted_message+','+str(user_id)
            
            client_one_socket.send(send_message.encode())
            
            user_data = {
                'user_id': user_id,
                'message': encrypted_message,
            }
            print('encrypted_in_main',encrypted_message)
            # insert into database the cipher
            insert_user_data('chat_rc4', user_data)
            
            # get messages history from database
            data = get_messages_all_with_user_id('chat_rc4')
            self.chat_history.delete(0, END)
            
            for item in data:
                current_id, current_str= item

                decrypted_message = rc4_decrypt(current_str)
                
                self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
            
        elif self.selected_technique == "ELGAMAL":
            print("ELGAMAL")
            
            # Key Generation
            public_key, private_key = Key_Generation_by_Alice(q, a)
            print(private_key)
            encrypted_message = encrypt_gamal(q, a,public_key ,message)
            
            
            
            # Convert list of lists to a string
            ciphertext_str = json.dumps(encrypted_message)
            
            send_message = str(self.selected_technique)+','+ ciphertext_str +','+str(private_key)+','+str(user_id)
            client_one_socket.send(send_message.encode())
            
            user_data = {
                'user_id': user_id,
                'message': ciphertext_str,
                'public_key' : str(private_key),
            }
            
            print('encrypted_in_main',ciphertext_str)
            #insert into database the cipher
            insert_user_data_gamal('chat_gamal', user_data)
            
            # get messages history from database
            data = get_messages_all_with_user_id_gamal('chat_gamal')
            self.chat_history.delete(0, END)
            
            for item in data:
                current_id, current_str, pk = item
                
                # Convert the string back to the original list of lists
                retrieved_list_of_lists = json.loads(current_str)


                decrypted_message = decrypt_gamal(q,int(pk) ,retrieved_list_of_lists)
                self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")


        elif self.selected_technique == "Playfair":
            print("Playfair")
            encrypted_text = encryption_playfair(message)
            
            send_message = str(self.selected_technique)+','+ encrypted_text+','+str(user_id)
            # send to server the data
            client_one_socket.send(send_message.encode())
        
            user_data = {
                'user_id': user_id,
                'message': encrypted_text
            }
            print('encrypted_in_main',encrypted_text)
            # insert into database the cipher
            insert_user_data('chat', user_data)
            
            # get messages history from database
            data = get_messages_all_with_user_id('chat')
            self.chat_history.delete(0, END)
            for item in data:
                current_id, current_str = item                
                decrypted_message = decryption_playfair(current_str)
                self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")


        elif self.selected_technique == "Caesar":
            print("Caesar")
            encrypted_text = caesar_cipher_encrypt(message)

            send_message = str(self.selected_technique)+','+ encrypted_text+','+str(user_id)
            # send to server the data
            client_one_socket.send(send_message.encode())
        
            user_data = {
                'user_id': user_id,
                'message': encrypted_text
            }
            print('encrypted_in_main',encrypted_text)
            insert_user_data('chat_Caesar', user_data)

            # get messages history from database
            data = get_messages_all_with_user_id('chat_caesar')
            self.chat_history.delete(0, END)
            for item in data:
                current_id, current_str = item                
                decrypted_message = caesar_cipher_decrypt(current_str)
                self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
            
                        
        elif self.selected_technique == "Row":
            print("Row")
            encrypted_text = Row_encrypt(message)

            send_message = str(self.selected_technique)+','+ encrypted_text+','+str(user_id)
            # send to server the data
            client_one_socket.send(send_message.encode())
        
            user_data = {
                'user_id': user_id,
                'message': encrypted_text
            }
            print('encrypted_in_main',encrypted_text)
            insert_user_data('chat_row', user_data)
            
            # get messages history from database
            data = get_messages_all_with_user_id('chat_row')
            self.chat_history.delete(0, END)
            for item in data:
                current_id, current_str = item                
                decrypted_message = Row_decrypt(current_str)
                self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
            

        elif self.selected_technique == "Mono":
            print("Mono")
            encrypted_text = mono_encryption(message)

            send_message = str(self.selected_technique)+','+ encrypted_text+','+str(user_id)
            # send to server the data
            client_one_socket.send(send_message.encode())
        
            user_data = {
                'user_id': user_id,
                'message': encrypted_text
            }
            print('encrypted_in_main',encrypted_text)
            insert_user_data('chat_mono', user_data)
            
            # get messages history from database
            data = get_messages_all_with_user_id('chat_mono')
            self.chat_history.delete(0, END)
            for item in data:
                current_id, current_str = item                
                decrypted_message = mono_decryption(current_str)
                self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")
            
            
        elif self.selected_technique == "Vigenere":
            print("Vigenere")
            encrypted_text = vigenere_cipher_encryption(message)

            send_message = str(self.selected_technique)+','+ encrypted_text+','+str(user_id)
            # send to server the data
            client_one_socket.send(send_message.encode())
        
            user_data = {
                'user_id': user_id,
                'message': encrypted_text
            }
            print('encrypted_in_main',encrypted_text)
            insert_user_data('chat_vigenere', user_data)
            
            # get messages history from database
            data = get_messages_all_with_user_id('chat_vigenere')
            self.chat_history.delete(0, END)
            for item in data:
                current_id, current_str = item                
                decrypted_message = vigenere_cipher_decryption(current_str)
                self.chat_history.insert(tk.END, f"User ID ({current_id}): {decrypted_message}\n")

        elif self.selected_technique == "Reil":
            print("Reil")
            # encrypted_message = encrypt_with_reil(message)
        
        
    # Function to handle receiving messages from the server
    def receive_messages(self):
        global decrypted_message_client_one, decrypted_id_client_one
        while True:
            try:
                data = client_one_socket.recv(4096).decode()
                print(f"Server says: {data}")
                result_list_client_one = data.split(',')

                print(result_list_client_one)
                decrypted_message_client_one = result_list_client_one[0]
                
                self.root.after(0, self.update_GUI)
                
                    
            except Exception as e:
                # Handle disconnection
                print("Connection to the server is closed due to.", e)
                break

if __name__ == "__main__":
    # Create the main window for encryption technique choosing
    root_encryption = tk.Tk()
    

    # Create an instance of the EncryptionChooser class
    encryption_chooser = EncryptionChooser(root_encryption)
    
    # Create a thread to handle the tasks separately
    server_thread = threading.Thread(target=server_main)
    
    # run the tasks together
    server_thread.start()

    
    root_encryption.mainloop()
    
    # Wait for other threads to finish
    server_thread.join()

    
    
"""     # Run the Tkinter event loop for encryption choosing
    root_encryption.mainloop() """
    


# %%
