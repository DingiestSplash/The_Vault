import customtkinter as ctk
import re
import bcrypt
import secrets
import string
from user_accounts import *

class Application:
    def __init__(self, root):
        self.root = root
        self.conn = connect_db()  # Make sure connect_db() is correctly returning a connection object.
        self.cursor = self.conn.cursor()  # Initialize cursor here.
        self.create_main_frame()
        
    def set_cursor(self, cursor):
        self.cursor = cursor

    def create_main_frame(self):
        # Destroy any existing frame first to clear the space
        try:
            self.frame.destroy()
        except AttributeError:
            pass  # If the frame does not exist yet, pass

        self.frame = ctk.CTkFrame(self.root)
        self.frame.place(relx=0.5, rely=0.5, anchor="center")

        # Create Account Button
        self.create_account_btn = ctk.CTkButton(self.frame, text="Create Account", command=self.create_account)
        self.create_account_btn.grid(row=0, column=0, padx=10, pady=10)

        # Login Button
        self.login_btn = ctk.CTkButton(self.frame, text="Login", command=self.login)
        self.login_btn.grid(row=1, column=0, padx=10, pady=10)

    def create_account(self):
        self.create_account_btn.grid_remove()
        self.login_btn.grid_remove()

        username_label = ctk.CTkLabel(self.frame, text="Username:")
        username_label.grid(row=0, column=0, padx=10, pady=5)

        self.username_entry_create = ctk.CTkEntry(self.frame)
        self.username_entry_create.grid(row=0, column=1, padx=10, pady=5)

        password_label = ctk.CTkLabel(self.frame, text="Password:")
        password_label.grid(row=1, column=0, padx=10, pady=5)

        self.password_entry_create = ctk.CTkEntry(self.frame, show="*")
        self.password_entry_create.grid(row=1, column=1, padx=10, pady=5)

        # Password criteria list
        criteria_label = ctk.CTkLabel(self.frame, text="Password must include at least:")
        criteria_label.grid(row=2, columnspan=2)

        criteria_list = [
        "8 characters minimum",
        "One uppercase letter",
        "One lowercase letter",
        "One digit",
        "One special character (!@#$%^&*(),.?\":{}|<>)"
        ]

        for index, criteria in enumerate(criteria_list, start=3):
            criteria_item = ctk.CTkLabel(self.frame, text="• " + criteria)
            criteria_item.grid(row=index, columnspan=2, sticky='w', padx=20)

        submit_btn = ctk.CTkButton(self.frame, text="Create Account", command=self.handle_account_creation)
        submit_btn.grid(row=9, columnspan=2, padx=10, pady=5)

        back_btn = ctk.CTkButton(self.frame, text="Back", command=self.create_main_frame)
        back_btn.grid(row=10, columnspan=2, pady=5)

    def is_password_strong(self, password):
        # Check the password strength criteria
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search("[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search("[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search("[0-9]", password):
            return False, "Password must contain at least one digit."
        if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character."
        return True, "Password is strong."

    def username_exists(self, username):
        self.cursor.execute('''SELECT COUNT(*) FROM accounts WHERE username = ?''', (username,))
        # Fetch the result and return True if the count is greater than 0, indicating the username exists
        return self.cursor.fetchone()[0] > 0

    def handle_account_creation(self):
        username = self.username_entry_create.get()
        password = self.password_entry_create.get()
        valid, message = self.is_password_strong(password)
        if not valid:
            error_label = ctk.CTkLabel(self.frame, text=message, fg_color="red")
            error_label.grid(row=3, columnspan=2)
            return
    
        if self.username_exists(username):
            error_label = ctk.CTkLabel(self.frame, text="Username already exists.", fg_color="red" )
            error_label.grid(row=8, columnspan=2)
            return
    
        try:
            # Hash the password using bcrypt
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
            # Insert the username and hashed password into the database
            insert_user(self.cursor, username, hashed_password.decode('utf-8'))  # Store the hashed password as a string
            self.conn.commit()
            self.frame.destroy()
            self.create_main_frame()
        except sqlite3.Error as e:
            print("Error inserting user:", e)
        

    def login(self):
        self.create_account_btn.grid_remove()
        self.login_btn.grid_remove()

        username_label = ctk.CTkLabel(self.frame, text="Username:")
        username_label.grid(row=0, column=0, padx=10, pady=5)

        self.username_entry_login = ctk.CTkEntry(self.frame)
        self.username_entry_login.grid(row=0, column=1, padx=10, pady=5)

        password_label = ctk.CTkLabel(self.frame, text="Password:")
        password_label.grid(row=1, column=0, padx=10, pady=5)

        self.password_entry_login = ctk.CTkEntry(self.frame, show="*")
        self.password_entry_login.grid(row=1, column=1, padx=10, pady=5)

        error_label = ctk.CTkLabel(self.frame, text="Usernames & Passwords are case sensitive.")
        error_label.grid(row=2, columnspan=2)

        submit_btn = ctk.CTkButton(self.frame, text="Login", command=lambda: self.handle_login(error_label))
        submit_btn.grid(row=3, columnspan=2, padx=10, pady=5)
        
        back_btn = ctk.CTkButton(self.frame, text="Back", command=self.create_main_frame)
        back_btn.grid(row=4, columnspan=2, pady=5)

    def handle_login(self, error_label):
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()
        user = fetch_user(self.cursor, username)

        if user and check_password(password, user[1]):
            error_label.configure(text="")
            self.frame.destroy()
            self.main_application(username)
        else:
            error_label.configure(text="Invalid username or password. Please try again.")
            self.password_entry_login.delete(0, 'end')

    def main_application(self, user):
        self.app_frame = ctk.CTkFrame(self.root)
        self.app_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=1.0, relheight=1.0)

        welcome_label = ctk.CTkLabel(self.app_frame, text=f"Welcome, {user}!")
        welcome_label.grid(padx=20, pady=20)

        logout_button = ctk.CTkButton(self.app_frame, text="Logout", command=lambda: self.logout(self.app_frame))
        logout_button.grid(padx=20, pady=20)

    def logout(self, frame):
        frame.destroy()
        self.create_main_frame()  # Recreate the initial login/create account frame
   
