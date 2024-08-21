Overview
SecureChat is a project designed to showcase basic encryption and decryption techniques using Python. The core idea is to develop a chat interface that securely transmits messages by encrypting them before sending and decrypting them upon receiving, without relying on any pre-built libraries for cryptographic functions.

Project Structure
GUI: A simple graphical user interface (GUI) mimicking a chat application, developed using Python's Tkinter library. The interface allows users to send and receive messages, which are displayed after decryption.

Encryption/Decryption Logic: The messages exchanged between users are encrypted and stored in a MySQL database. The encryption and decryption processes are custom-built without any ready-made cryptographic functions.

Features
Custom Encryption Algorithm: A unique encryption method is implemented, converting plain text messages into binary format and then applying a series of bitwise operations to secure the data.

Decryption: The encrypted binary message is retrieved from the database, decrypted using the custom algorithm, and displayed in the chat interface.

MySQL Database: Messages are stored in a MySQL database in their encrypted form, ensuring data security during storage.

How it Works
1. User Interface
The chat interface displays the conversation between two users (e.g., Khaled and Hany). Each user’s message is encrypted before being displayed on the interface and stored in the database.

2. Encryption
When a user sends a message, the text is first converted into its binary equivalent. A custom encryption algorithm then scrambles this binary data through bitwise operations, making the original message unintelligible.

3. Database Storage
Encrypted messages are stored in a MySQL database. Each record in the database corresponds to a single message, identified by a unique user_id and receiver_id.

4. Decryption
Upon retrieval, the encrypted message is decrypted using the reverse process of the encryption algorithm. The binary data is reverted to its original text form and displayed in the chat window.

Example
Stored Data
An example of a stored encrypted message in the MySQL database:

Message (Binary Format):
Copy code
1101111011010000010011001101001010100000000101111001000010...
User ID: 1
Receiver ID: 2
Decrypted Message
The above binary data, when decrypted, translates back into the original message, e.g., hello.
