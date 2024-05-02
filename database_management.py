import sqlite3
import bcrypt
import base64
import os
from cryptography.fernet import Fernet

# Generate a key and save it securely; for demonstration, we'll generate it dynamically
# In production, store this key securely and load it from a secure location
key = Fernet.generate_key()
cipher = Fernet(key)

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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secure_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title BLOB,
            note BLOB,
            FOREIGN KEY (user_id) REFERENCES accounts(id)
        )''')
    conn.commit()


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


class EncryptionService:
    def __init__(self, key_path="master_key.key"):
        self.key_path = key_path
        self.key = self.load_or_generate_key()
        self.cipher = Fernet(self.key)

    def load_or_generate_key(self):
        if not os.path.exists(self.key_path):
            key = Fernet.generate_key()
            with open(self.key_path, "wb") as key_file:
                key_file.write(key)
            os.chmod(self.key_path, 0o600)
        else:
            with open(self.key_path, "rb") as key_file:
                key = key_file.read()
        return key

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.cipher.encrypt(data)

    def decrypt(self, encrypted_data):
        if isinstance(encrypted_data, bytes):
            return self.cipher.decrypt(encrypted_data).decode('utf-8')
        else:
            print(f"Unexpected data type for decryption: {type(encrypted_data).__name__}")
            return "Decryption Error"  # or handle differently



class PasswordVaultManager:
    def __init__(self, db_connection, user_id, encryption_service):
        self.db = db_connection
        self.user_id = user_id
        self.encryption_service = encryption_service

    # Replace the direct encryption/decryption calls with calls to the encryption service
    def add_password_record(self, website, username, password):
    # Encrypt the data
        encrypted_website = self.encryption_service.encrypt(website)
        encrypted_username = self.encryption_service.encrypt(username)
        encrypted_password = self.encryption_service.encrypt(password)
    
    # Prepare the SQL query to insert the encrypted data
        query = '''
        INSERT INTO passwords (user_id, website, username, password)
        VALUES (?, ?, ?, ?)
        '''
    
    # Create a cursor and execute the insert command
        cursor = self.db.cursor()
        try:
            cursor.execute(query, (self.user_id, encrypted_website, encrypted_username, encrypted_password))
            self.db.commit()  # Commit the transaction to save the data in the database
        except sqlite3.Error as e:
            print(f"Failed to add password record to the database: {e}")
        finally:
            cursor.close()

    def get_all_passwords_for_user(self):
        cursor = self.db.cursor()
        cursor.execute("SELECT id, website, username, password FROM passwords WHERE user_id = ?", (self.user_id,))
        entries = cursor.fetchall()
        decrypted_entries = []
        for id, website, username, password in entries:
            decrypted_website = self.encryption_service.decrypt(website)
            decrypted_username = self.encryption_service.decrypt(username)
            decrypted_password = self.encryption_service.decrypt(password)
            decrypted_entries.append((id, decrypted_website, decrypted_username, decrypted_password))
        return decrypted_entries

    def update_password_record(self, record_id, website, username, password):
        try:
            encrypted_website = self.encryption_service.encrypt(website)
            encrypted_username = self.encryption_service.encrypt(username)
            encrypted_password = self.encryption_service.encrypt(password)
        except Exception as e:
            print(f"Failed to encrypt data: {e}")
            return

        cursor = self.db.cursor()
        try:
            query = "UPDATE passwords SET website = ?, username = ?, password = ? WHERE id = ? AND user_id = ?"
            cursor.execute(query, (encrypted_website, encrypted_username, encrypted_password, record_id, self.user_id))
            self.db.commit()
        except Exception as e:
            print(f"Database update failed: {e}")
        finally:
            cursor.close()

    def delete_password_record(self, record_id):
        cursor = self.db.cursor()
        try:
            cursor.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", (record_id, self.user_id))
            self.db.commit()
        finally:
            cursor.close()
            
   
    
    
class SecureNotesManager:
    def __init__(self, db_connection, user_id, encryption_service):
        self.db = db_connection
        self.user_id = user_id
        self.encryption_service = encryption_service

    def encrypt(self, data):
        return self.encryption_service.encrypt(data)

    def decrypt(self, encrypted_data):
        return self.encryption_service.decrypt(encrypted_data)

    def save_note(self, title, note):
        encrypted_title = self.encrypt(title)  # Encrypt the title
        encrypted_note = self.encrypt(note)    # Encrypt the note
        cursor = self.db.cursor()
        try:
            cursor.execute("INSERT INTO secure_notes (user_id, title, note) VALUES (?, ?, ?)",
                       (self.user_id, encrypted_title, encrypted_note))
            self.db.commit()
        finally:
            cursor.close()

    def retrieve_titles(self):
        cursor = self.db.cursor()
        try:
            cursor.execute("SELECT id, title FROM secure_notes WHERE user_id = ?", (self.user_id,))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        titles = []
        for id, title in rows:
            if isinstance(title, (bytes, bytearray)):  # Ensure it is in byte format
                decrypted_title = self.decrypt(title)
                titles.append((id, decrypted_title if decrypted_title is not None else "Decryption Error"))
            else:
                print(f"Title is not in byte format: {type(title).__name__}")
                titles.append((id, "Format Error"))  # Indicate format error in UI
        return titles


    def get_note_by_id(self, note_id):
        cursor = self.db.cursor()
        cursor.execute("SELECT title, note FROM secure_notes WHERE id = ?", (note_id,))
        note_data = cursor.fetchone()
        if note_data:
            decrypted_title = self.decrypt(note_data[0])
            decrypted_note = self.decrypt(note_data[1])
            cursor.close()
            return {'title': decrypted_title, 'content': decrypted_note}
        cursor.close()
        return None

    def delete_note(self, note_id):
        cursor = self.db.cursor()
        cursor.execute("DELETE FROM secure_notes WHERE id = ?", (note_id,))
        self.db.commit()
        cursor.close()

    def update_note(self, note_id, title, note):
        encrypted_title = self.encrypt(title)
        encrypted_note = self.encrypt(note)
        cursor = self.db.cursor()
        cursor.execute("UPDATE secure_notes SET title = ?, note = ? WHERE id = ?",
                       (encrypted_title, encrypted_note, note_id))
        self.db.commit()
        cursor.close()















