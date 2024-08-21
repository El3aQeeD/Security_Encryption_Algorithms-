import socket
import threading

server_running = True
# Function to handle each client separately
def handle_client(client_socket, client_address):
    print(f"Connection established with {client_address}")

    # Receive the client name
    client_name = client_socket.recv(1024).decode()
    print(f"{client_name} joined the chat!")


    while True:
        # Receive data from the client
        data = client_socket.recv(4096).decode()
        if not data:
            break
        else:
            print(f"{client_name}: {data}")

            # Broadcast the message to other clients
            broadcast(f"{data}", client_socket)


    # Close the connection with the client
    client_socket.close()
    print(f"Connection closed with {client_address}")

# Function to broadcast a message to all connected clients
def broadcast(message, sender_socket):
    for client in clients:
        # Send the message to all clients except the sender
        if client != sender_socket:
            try:
                print('sent to all')
                client.send(message.encode())
            except:
                print('client removed')
                # Remove the broken connection
                clients.remove(client)

# Define the server address (host, port)
server_address = ('localhost', 12346)

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the server address
server_socket.bind(server_address)

# Listen for incoming connections (max 5 connections in the queue)
server_socket.listen(5)

print(f"Server is listening on {server_address}")

# List to store all connected clients
clients = []
def server_main():
    print('server_main')
    while True:
        if server_running == False:
            print('server closed')
            server_socket.close()
        # Wait for a connection
        print("Waiting for a connection...")
        client_socket, client_address = server_socket.accept()

        # Add the new client to the list
        clients.append(client_socket)
        print(len(clients))

        # Create a thread to handle the client separately
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

