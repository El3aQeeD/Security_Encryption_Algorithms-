
import mysql.connector
import asyncio

connection = None
Name = None
def connect_db(host = "localhost", user = "root", password = "", database = "security_database"):
    global connection
    # Establish a connection to the MySQL server
    try:
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        
        if connection.is_connected():
            print("Connected to MySQL database")

                    
    except Exception as e:
        print(f"Error: {e}")

def get_user_name_by_id(user_id, table_name):
    global Name
    # Perform a query to get the name of a specific ID
    try:
        cursor =  connection.cursor()

        # Example query with a parameterized value
        query =  f"SELECT Name FROM {table_name} WHERE ID = {user_id}"
        print(query)
        cursor.execute(query)

        # Fetch the row
        row = cursor.fetchone()

        if row:
            print(f"Name for ID {user_id}: {row[0]}")
            Name = row[0]
            return Name
        else:
            print(f"No record found for ID {user_id}")
            return False

    except Exception as e:
        print(f"Error executing query: {e}")
        return False

    finally:
        # Close the cursor
        if 'cursor' in locals():
            cursor.close()

def insert_user_data(table_name, user_data):
    try:
        cursor = connection.cursor()

        # Example query with parameterized values
        query = f"INSERT INTO {table_name} (user_id, message, reciver_id) VALUES (%s, %s, %s)"
        
        # Assuming user_data is a dictionary containing user information
        values = (user_data['user_id'], user_data['message'], 2)

        cursor.execute(query, values)

        # Commit the changes
        connection.commit()

        print("message inserted successfully")
        return True
        

    except Exception as e:
        print(f"Error inserting user: {e}")
        # Rollback the changes if an error occurs
        connection.rollback()
        return False

    finally:
        # Close the cursor
        if 'cursor' in locals():
            cursor.close()
            
def insert_user_data_rsa(table_name, user_data):
    try:
        cursor = connection.cursor()

        # Example query with parameterized values
        query = f"INSERT INTO {table_name} (user_id, message, n, d) VALUES (%s, %s,%s,%s)"
        
        # Assuming user_data is a dictionary containing user information
        values = (user_data['user_id'], user_data['message'], user_data['n'], user_data['d'])

        cursor.execute(query, values)

        # Commit the changes
        connection.commit()

        print("message inserted successfully")
        return True
        

    except Exception as e:
        print(f"Error inserting user: {e}")
        # Rollback the changes if an error occurs
        connection.rollback()
        return False

    finally:
        # Close the cursor
        if 'cursor' in locals():
            cursor.close()

def insert_user_data_gamal(table_name, user_data):
    try:
        cursor = connection.cursor()

        # Example query with parameterized values
        query = f"INSERT INTO {table_name} (user_id, message, public_key) VALUES (%s, %s,%s)"
        
        # Assuming user_data is a dictionary containing user information
        values = (user_data['user_id'], user_data['message'], user_data['public_key'])

        cursor.execute(query, values)

        # Commit the changes
        connection.commit()

        print("message inserted successfully")
        return True
        

    except Exception as e:
        print(f"Error inserting user: {e}")
        # Rollback the changes if an error occurs
        connection.rollback()
        return False

    finally:
        # Close the cursor
        if 'cursor' in locals():
            cursor.close()

def get_user_messages_by_id(user_id, table_name):
    try:
        cursor = connection.cursor()

        # Example query with a parameterized value
        query = f"SELECT message FROM {table_name} WHERE user_id = %s"
        
        # Parameterized value for the query
        user_id_param = (user_id,)

        cursor.execute(query, user_id_param)

        # Fetch all the rows
        rows = cursor.fetchall()

        if rows:
            messages = [row[0] for row in rows]
            print(f"Messages for ID {user_id}: {messages}")
            return messages
        else:
            print(f"No messages found for ID {user_id}")
            return False

    except Exception as e:
        print(f"Error executing query: {e}")
        return False

    finally:
        # Close the cursor
        if 'cursor' in locals():
            cursor.close()


def get_messages_all_with_user_id(table_name):
    try:
        with connection.cursor() as cursor:
            # Example query to retrieve user_id and message for all messages
            query = f"SELECT user_id, message FROM {table_name} ORDER BY time"

            cursor.execute(query)

            # Fetch all the rows
            rows = cursor.fetchall()

            if rows:
                messages_with_user_id = [(row[0], row[1]) for row in rows]
                print(f"All Messages with User ID: {messages_with_user_id}")
                return messages_with_user_id
            else:
                print(f"No messages found")
                return []

    except Exception as e:
        print(f"Error executing query: {e}")
        return []

def get_messages_all_with_user_id(table_name):
    try:
        with connection.cursor() as cursor:
            # Example query to retrieve user_id and message for all messages
            query = f"SELECT user_id, message FROM {table_name} ORDER BY time"

            cursor.execute(query)

            # Fetch all the rows
            rows = cursor.fetchall()

            if rows:
                messages_with_user_id = [(row[0], row[1]) for row in rows]
                print(f"All Messages with User ID: {messages_with_user_id}")
                return messages_with_user_id
            else:
                print(f"No messages found")
                return []

    except Exception as e:
        print(f"Error executing query: {e}")
        return []


def get_messages_all_with_user_id_rsa(table_name):
    try:
        with connection.cursor() as cursor:
            # Example query to retrieve user_id and message for all messages
            query = f"SELECT user_id, message,n,d FROM {table_name} ORDER BY time"

            cursor.execute(query)

            # Fetch all the rows
            rows = cursor.fetchall()

            if rows:
                messages_with_user_id = [(row[0], row[1],row[2],row[3]) for row in rows]
                print(f"All Messages with User ID: {messages_with_user_id}")
                return messages_with_user_id
            else:
                print(f"No messages found")
                return []

    except Exception as e:
        print(f"Error executing query: {e}")
        return []

def get_messages_all_with_user_id_gamal(table_name):
    try:
        with connection.cursor() as cursor:
            # Example query to retrieve user_id and message for all messages
            query = f"SELECT user_id, message,public_key FROM {table_name} ORDER BY time"

            cursor.execute(query)

            # Fetch all the rows
            rows = cursor.fetchall()

            if rows:
                messages_with_user_id = [(row[0], row[1],row[2]) for row in rows]
                print(f"All Messages with User ID: {messages_with_user_id}")
                return messages_with_user_id
            else:
                print(f"No messages found")
                return []

    except Exception as e:
        print(f"Error executing query: {e}")
        return []