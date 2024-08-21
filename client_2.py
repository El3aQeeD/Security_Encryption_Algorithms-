import socket
import threading
from database import *

# Function to handle receiving messages from the server
def receive_messages():
    while True:
        try:
            data = client_socket.recv(1024).decode()
            print(f"Server says: {data}")
        except:
            # Handle disconnection
            print("Connection to the server is closed.")
            break

# Define the server address (host, port)
server_address = ('localhost', 12345)

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_socket.connect(server_address)


# connect the database
connect_db()

# Get user name from database if it exists
user_exist = get_user_name_by_id(2, 'user')

if user_exist:
    # Send the client name to the server
    client_socket.send(user_exist.encode())

# Start a thread to receive messages from the server
receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

# Main loop to send messages to the server
def main_clint_two():
    print('client_two_main')
    while True:
        message = input(f"{user_exist} Enter your message: ")
        client_socket.send(message.encode())

#main_clint_one()