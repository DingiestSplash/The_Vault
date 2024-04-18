import customtkinter as ctk
import re
import bcrypt
import secrets
import string
import pyperclip
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

        # Add password confirmation entry
        password_confirm_label = ctk.CTkLabel(self.frame, text="Confirm Password:")
        password_confirm_label.grid(row=2, column=0, padx=10, pady=5)
        self.password_entry_confirm = ctk.CTkEntry(self.frame, show="*")
        self.password_entry_confirm.grid(row=2, column=1, padx=10, pady=5)

        self.password_entry_create = ctk.CTkEntry(self.frame, show="*")
        self.password_entry_create.grid(row=1, column=1, padx=10, pady=5)

        # Password criteria list
        criteria_label = ctk.CTkLabel(self.frame, text="Password must include at least:")
        criteria_label.grid(row=3, columnspan=2)

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
        password_confirm = self.password_entry_confirm.get()

        if password != password_confirm:
            error_label = ctk.CTkLabel(self.frame, text="Passwords do not match.", fg_color="red")
            error_label.grid(row=8, columnspan=2)
            return

        valid, message = self.is_password_strong(password)
        if not valid:
            error_label = ctk.CTkLabel(self.frame, text=message, fg_color="red")
            error_label.grid(row=3, columnspan=2)
            return

        if self.username_exists(username):
            error_label = ctk.CTkLabel(self.frame, text="Username already exists.", fg_color="red")
            error_label.grid(row=8, columnspan=2)
            return

        try:
        # Hash the password using bcrypt, directly storing the bytes
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            insert_user(self.cursor, username, hashed_password)  # Pass bytes directly to insert_user
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

        if user:
            # Ensure that the password is passed as bytes if stored as a string in the database
            stored_password = user[1].encode('utf-8') if isinstance(user[1], str) else user[1]
            if check_password(password, stored_password):
                error_label.configure(text="")
                self.frame.destroy()
                self.main_application(username)
            else:
                error_label.configure(text="Invalid password. Please try again.")
                self.password_entry_login.delete(0, 'end')
        else:
            error_label.configure(text="Invalid username. Please try again.")


    def main_application(self, user):
        self.app_frame = ctk.CTkFrame(self.root)
        self.app_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=1.0, relheight=1.0)

        # Navigation bar frame
        nav_bar_frame = ctk.CTkFrame(self.app_frame)
        nav_bar_frame.grid(row=0, column=0, padx=20, pady=10, sticky="ew")

        # Password Generator Button
        pw_gen_button = ctk.CTkButton(nav_bar_frame, text="Password Generator", command=self.open_password_generator)
        pw_gen_button.grid(row=0, column=0, padx=10)

        # Password Vault Button
        pw_vault_button = ctk.CTkButton(nav_bar_frame, text="Password Vault", command=self.open_password_vault)
        pw_vault_button.grid(row=0, column=1, padx=10)

        # Secure Notes Button
        secure_notes_button = ctk.CTkButton(nav_bar_frame, text="Secure Notes", command=self.open_secure_notes)
        secure_notes_button.grid(row=0, column=2, padx=10)

        # Logout Button
        logout_button = ctk.CTkButton(nav_bar_frame, text="Logout", command=lambda: self.logout(self.app_frame))
        logout_button.grid(row=0, column=3, padx=10)

    def open_password_generator(self):
        # Destroy current app frame and recreate for password generator
        self.app_frame.destroy()
        self.app_frame = ctk.CTkFrame(self.root)
        self.app_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=1.0, relheight=1.0)

        # Re-create navigation bar in the new frame
        nav_bar_frame = ctk.CTkFrame(self.app_frame)
        nav_bar_frame.grid(row=0, column=0, padx=20, pady=10, sticky="ew")

        # Re-add navigation buttons
        pw_gen_button = ctk.CTkButton(nav_bar_frame, text="Password Generator", command=self.open_password_generator)
        pw_gen_button.grid(row=0, column=0, padx=10)

        pw_vault_button = ctk.CTkButton(nav_bar_frame, text="Password Vault", command=self.open_password_vault)
        pw_vault_button.grid(row=0, column=1, padx=10)

        secure_notes_button = ctk.CTkButton(nav_bar_frame, text="Secure Notes", command=self.open_secure_notes)
        secure_notes_button.grid(row=0, column=2, padx=10)

        logout_button = ctk.CTkButton(nav_bar_frame, text="Logout", command=lambda: self.logout(self.app_frame))
        logout_button.grid(row=0, column=3, padx=10)

        # Generate Password button
        generate_btn = ctk.CTkButton(self.app_frame, text="Generate Password", command=self.generate_strong_password)
        generate_btn.grid(row=1, column=0, padx=20, pady=20)

        # Password display box
        self.password_display = ctk.CTkEntry(self.app_frame, width=200)
        self.password_display.grid(row=2, column=0, padx=20, pady=10)

        # Copy button
        copy_btn = ctk.CTkButton(self.app_frame, text="Copy", command=self.copy_to_clipboard)
        copy_btn.grid(row=3, column=0, padx=10, pady=10)


    def copy_to_clipboard(self):
        password = self.password_display.get()
        pyperclip.copy(password)

        # Check if the copied label exists already, if not create it
        if not hasattr(self, 'copied_label'):
            self.copied_label = ctk.CTkLabel(self.app_frame, text="Copied!")
            # Assuming the button is at row 1, column 0
            self.copied_label.grid(row=4, column=0, pady=(5, 0))  # Adjust grid position as needed

        # Make the copied label visible
        self.copied_label.grid()

        # Schedule the copied label to be hidden after 1.5 seconds
        self.root.after(1500, lambda: self.copied_label.grid_remove())





    def generate_strong_password(self):
        # Example function to generate a strong password
        characters = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
        strong_password = ''.join(secrets.choice(characters) for i in range(12))  # Generates a 12-character password
        self.password_display.delete(0, 'end')  # Clear the previous password
        self.password_display.insert(0, strong_password)  # Display the generated password

    def open_password_vault(self):
        # Placeholder for Password Vault functionality
        print("Opening Password Vault")
        
    def open_secure_notes(self):
        # Placeholder for Secure Notes functionality
        print("Opening Secure Notes")

    def logout(self, frame):
        frame.destroy()
        self.create_main_frame()  # Recreate the initial login/create account frame
