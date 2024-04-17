import sqlite3
import bcrypt
import base64

def connect_db():
    conn = sqlite3.connect("encrypted_accounts.db")
    create_user_table(conn.cursor())  # Ensure table exists before returning the connection
    return conn

def create_user_table(cursor):
    cursor.execute('''CREATE TABLE IF NOT EXISTS accounts
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       username TEXT,
                       password BLOB)''')
    cursor.connection.commit()  # Commit the changes to the database

def insert_user(cursor, username, password):
    # Assume password is already a bytes object (the output from bcrypt.hashpw)
    encoded_password = base64.b64encode(password).decode('utf-8')  # Encode to base64 and then decode to string for storage
    cursor.execute("INSERT INTO accounts (username, password) VALUES (?, ?)",
                   (username, encoded_password))

def fetch_user(cursor, username):
    cursor.execute("SELECT username, password FROM accounts WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user:
        # Base64 decode the password after fetching
        user = (user[0], base64.b64decode(user[1]))
    return user


def check_password(user_password, stored_password):
    # Assuming stored_password is fetched as bytes from the database
    return bcrypt.checkpw(user_password.encode('utf-8'), stored_password)



