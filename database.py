import sqlite3
import bcrypt

def connect_db():
    return sqlite3.connect("encrypted_accounts.db")

def create_user_table(cursor):
    cursor.execute('''CREATE TABLE IF NOT EXISTS accounts
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       username TEXT,
                       password BLOB)''')

def insert_user(cursor, username, password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    cursor.execute("INSERT INTO accounts (username, password) VALUES (?, ?)",
                   (username, hashed_password))

def fetch_user(cursor, username):
    cursor.execute("SELECT username, password FROM accounts WHERE username = ?", (username,))
    return cursor.fetchone()

def check_password(user_password, stored_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), stored_password)
