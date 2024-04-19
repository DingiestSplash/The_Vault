import sqlite3
import bcrypt
import base64
from cryptography.fernet import Fernet

# Encryption setup for password manager data
key = Fernet.generate_key()
cipher_suite = Fernet(key)


def connect_db(db_path="encrypted_accounts.db"):
    """Connect to the SQLite database and ensure all necessary tables are created."""
    try:
        conn = sqlite3.connect(db_path)
        create_tables(conn)
        return conn
    except sqlite3.Error as e:
        print(f"An error occurred while connecting to the database: {e}")
        # Depending on your application's requirements, you might raise the exception
        # or handle it in another way (e.g., retrying the connection)
        raise

def create_tables(conn):
    """Create database tables if they don't already exist."""
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password BLOB
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                website TEXT,
                username TEXT,
                encrypted_password BLOB,
                FOREIGN KEY (user_id) REFERENCES accounts(id)
            )''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"An error occurred while creating tables: {e}")
        raise



class UserAccountManager:
    def __init__(self, db_connection):
        self.db = db_connection
        self.cursor = self.db.cursor()
        
    def insert_user(self, username, password):
    # Assume password is already a bytes object (the output from bcrypt.hashpw)
        encoded_password = base64.b64encode(password).decode('utf-8')  # Encode to base64 and then decode to string for storage
        self.cursor.execute("INSERT INTO accounts (username, password) VALUES (?, ?)",
                   (username, encoded_password))

    def fetch_user(self, username):
        self.cursor.execute("SELECT username, password FROM accounts WHERE username = ?", (username,))
        user = self.cursor.fetchone()
        if user:
        # Base64 decode the password if you're using base64 encoding
            user = (user[0], base64.b64decode(user[1].encode('utf-8')))
        return user

    def check_password(self, user_password, stored_password):
        return bcrypt.checkpw(user_password, stored_password)
    
    def username_exists(self, username):
        """Check if a username already exists in the database."""
        self.cursor.execute("SELECT COUNT(*) FROM accounts WHERE username = ?", (username,))
        count = self.cursor.fetchone()[0]
        return count > 0

class PasswordVaultManager:
    def __init__(self, db_connection, user_id):
        self.db = db_connection
        self.user_id = user_id  

    def add_password_record(cursor, user_id, website, username, password):
        encrypted_password = cipher_suite.encrypt(password.encode('utf-8'))
        cursor.execute("INSERT INTO passwords (user_id, website, username, encrypted_password) VALUES (?, ?, ?, ?)",
                    (user_id, website, username, encrypted_password))
        cursor.connection.commit()

    def update_password_record(cursor, record_id, website, username, password):
        encrypted_password = cipher_suite.encrypt(password.encode('utf-8'))
        cursor.execute("UPDATE passwords SET website = ?, username = ?, encrypted_password = ? WHERE id = ?",
                   (website, username, encrypted_password, record_id))
        cursor.connection.commit()

    def delete_password_record(cursor, record_id):
        cursor.execute("DELETE FROM passwords WHERE id = ?", (record_id,))
        cursor.connection.commit()








