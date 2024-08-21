""" import socket
import threading
from database import *
from Simple_chat_App import WhatsApp
import tkinter as tk
import time
import pickle
from DES_Algorithm import *
from PlayFair import *
decrypted_id_client_one = None
decrypted_message_client_one = None
# Function to handle receiving messages from the server
def receive_messages():
    global decrypted_message_client_one, decrypted_id_client_one
    while True:
        try:
            data = client_one_socket.recv(4096).decode()
            print(f"Server says: {data}")
            result_list_client_one = data.split(',')

            print(result_list_client_one)
            
            if result_list_client_one[0] == 'DES':
                print('DES')
            elif result_list_client_one[0] == 'Playfair':
                decrypted_message_client_one = decryption_playfair(result_list_client_one[1])
                decrypted_id_client_one = result_list_client_one[2]
                print('in client dec', decrypted_message_client_one)
            
        except Exception as e:
            # Handle disconnection
            print("Connection to the server is closed due to.", e)
            break

# Define the server address (host, port)
server_address = ('localhost', 12345)

# Create a socket object
client_one_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_one_socket.connect(server_address)


# connect the database
connect_db()

# Get user name from database if it exists
user_exist = get_user_name_by_id(1, 'user')

if user_exist:
    # Send the client name to the server
    client_one_socket.send(user_exist.encode())

# Start a thread to receive messages from the server
receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()
 """