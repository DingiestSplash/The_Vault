import sqlite3
import bcrypt
import base64

def connect_db(db_path="the_vault.db"):
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
                password BLOB,
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
        encoded_password = base64.b64encode(password).decode('utf-8')
        self.cursor.execute("INSERT INTO accounts (username, password) VALUES (?, ?)",
                            (username, encoded_password))

    def fetch_user(self, username):
        self.cursor.execute("SELECT id, password FROM accounts WHERE username = ?", (username,))
        user = self.cursor.fetchone()
        if user:
            # Return user ID and base64 decoded password
            return user[0], base64.b64decode(user[1].encode('utf-8'))
        return None

    def check_password(self, user_password, stored_password):
        return bcrypt.checkpw(user_password, stored_password)

    def username_exists(self, username):
        """Check if a username already exists in the database."""
        self.cursor.execute("SELECT COUNT(*) FROM accounts WHERE username = ?", (username,))
        return self.cursor.fetchone()[0] > 0

class PasswordVaultManager:
    def __init__(self, db_connection, user_id):
        self.db = db_connection
        self.user_id = user_id
        self.db_path = "the_vault.db"

    def add_password_record(self, website, username, password):
        # Directly use user_id and store the password directly
        self.cursor = self.db.cursor()
        self.cursor.execute("INSERT INTO passwords (user_id, website, username, password) VALUES (?, ?, ?, ?)",
                            (self.user_id, website, username, password.encode('utf-8')))
        self.db.commit()

    def get_all_passwords_for_user(self):
        self.cursor = self.db.cursor()
        try:
            self.cursor.execute("SELECT id, website, username, password FROM passwords WHERE user_id = ?", (self.user_id,))
            return [(id, website, username, password.decode('utf-8')) for id, website, username, password in self.cursor.fetchall()]
        finally:
            self.cursor.close()
            
    def delete_password_record(self, record_id):
        conn = sqlite3.connect(self.db_path)  # Using db_path that was initialized
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM passwords WHERE id = ?", (record_id,))
            conn.commit()
        except Exception as e:
            raise e
        finally:
            conn.close()











