import customtkinter as ctk
import tkinter.simpledialog as simpledialog
import tkinter.messagebox as messagebox
import re
import bcrypt
import secrets
import string
import pyperclip
from database_management import *


class Application:
    def __init__(self, root):
        self.root = root
        self.db_connection = connect_db()
        self.user_manager = UserAccountManager(self.db_connection)
        self.password_manager = None  # This will be initialized after login
        self.initial_frame()
           
    def set_cursor(self, cursor):
        self.cursor = cursor

    # Initial Frame on First Load - Create Account/Login
    def initial_frame(self):
        try:
            self.frame.destroy()
        except AttributeError:
            pass

        self.frame = ctk.CTkFrame(self.root)
        self.frame.place(relx=0.5, rely=0.5, anchor="center")

        self.create_account_btn = ctk.CTkButton(self.frame, text="Create Account", command=self.create_account)
        self.create_account_btn.grid(row=0, column=0, padx=10, pady=10)

        self.login_btn = ctk.CTkButton(self.frame, text="Login", command=self.login)
        self.login_btn.grid(row=1, column=0, padx=10, pady=10)

    # Create Account Frame & Functions
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

        back_btn = ctk.CTkButton(self.frame, text="Back", command=self.initial_frame)
        back_btn.grid(row=10, columnspan=2, pady=5)

    def is_password_strong(self, password):
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
        return self.user_manager.username_exists(username)

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
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            self.user_manager.insert_user(username, hashed_password)
            self.db_connection.commit()
            self.frame.destroy()
            self.initial_frame()
        except sqlite3.Error as e:
            print("Error inserting user:", e)

    # Login Frame & Functions
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
        
        back_btn = ctk.CTkButton(self.frame, text="Back", command=self.initial_frame)
        back_btn.grid(row=4, columnspan=2, pady=5)

    def handle_login(self, error_label):
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()
        user = self.user_manager.fetch_user(username)

        if user:
            stored_password = user[1]
            if self.user_manager.check_password(password.encode('utf-8'), stored_password):
                error_label.configure(text="Login successful!", fg_color="green")
                self.frame.destroy()
                user_id = user[0]  # Extract user ID
                self.password_manager = PasswordVaultManager(self.db_connection, user_id)  # Initialize PasswordVaultManager
                self.main_application(username)
            else:
                error_label.configure(text="Invalid password. Please try again.", fg_color="red")
                self.password_entry_login.delete(0, 'end')
        else:
            error_label.configure(text="Invalid username. Please try again.", fg_color="red")


    # Navigation Buttons
    def create_nav_buttons(self, nav_bar_frame):
        pw_gen_button = ctk.CTkButton(nav_bar_frame, text="Password Generator", command=self.password_generator)
        pw_gen_button.grid(row=0, column=0, padx=10)

        pw_vault_button = ctk.CTkButton(nav_bar_frame, text="Password Vault", command=self.password_vault)
        pw_vault_button.grid(row=0, column=1, padx=10)

        secure_notes_button = ctk.CTkButton(nav_bar_frame, text="Secure Notes", command=self.open_secure_notes)
        secure_notes_button.grid(row=0, column=2, padx=10)

        logout_button = ctk.CTkButton(nav_bar_frame, text="Logout", command=lambda: self.logout(self.app_frame))
        logout_button.grid(row=0, column=3, padx=10)


    # Main Frame - User is now logged in. 
    # Still not sure what to put on this frame, maybe just welcome message and logo for application.
    # Really depend how much i expand this application.
    def main_application(self, user):
        self.app_frame = ctk.CTkFrame(self.root)
        self.app_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=1.0, relheight=1.0)

        nav_bar_frame = ctk.CTkFrame(self.app_frame)
        nav_bar_frame.grid(row=0, column=0, padx=20, pady=5, sticky="ew")
        self.create_nav_buttons(nav_bar_frame)

    # Password Generator Extension
    def password_generator(self):
        self.app_frame.destroy()
        self.app_frame = ctk.CTkFrame(self.root)
        self.app_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=1.0, relheight=1.0)

        nav_bar_frame = ctk.CTkFrame(self.app_frame)
        nav_bar_frame.grid(row=0, column=0, padx=20, pady=5, sticky="ew")
        self.create_nav_buttons(nav_bar_frame)

        generate_btn = ctk.CTkButton(self.app_frame, text="Generate Password", command=self.generate_strong_password)
        generate_btn.grid(row=1, column=0, padx=20, pady=20)

        self.password_display = ctk.CTkEntry(self.app_frame, width=200)
        self.password_display.grid(row=2, column=0, padx=20, pady=10)

        copy_btn = ctk.CTkButton(self.app_frame, text="Copy", command=self.copy_to_clipboard)
        copy_btn.grid(row=3, column=0, padx=10, pady=10)

    def copy_to_clipboard(self):
        password = self.password_display.get()
        pyperclip.copy(password)

        if not hasattr(self, 'copied_label'):
            self.copied_label = ctk.CTkLabel(self.app_frame, text="Copied!")
            self.copied_label.grid(row=4, column=0, pady=(5, 0))

        self.copied_label.grid()

        self.root.after(1500, lambda: self.copied_label.grid_remove())

    def generate_strong_password(self):
        characters = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
        strong_password = ''.join(secrets.choice(characters) for i in range(12))  # Generates a 12-character password
        self.password_display.delete(0, 'end')  # Clear the previous password
        self.password_display.insert(0, strong_password)  # Display the generated password


    # Password Vault Extension
    def password_vault(self):
        self.app_frame.destroy()
        self.app_frame = ctk.CTkFrame(self.root)
        self.app_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=1.0, relheight=1.0)

        nav_bar_frame = ctk.CTkFrame(self.app_frame)
        nav_bar_frame.grid(row=0, column=0, padx=20, pady=5, sticky="ew")
        self.create_nav_buttons(nav_bar_frame)
        
        new_entry_frame = ctk.CTkFrame(self.app_frame)
        new_entry_frame.grid(row=1, column= 0, padx=20, pady=5, sticky="ew")
        
        new_entry_website_label = ctk.CTkLabel(new_entry_frame, text="Website:")
        new_entry_website_label.grid(row=0, column=0, padx=10, pady=1)        
        self.new_entry_website = ctk.CTkEntry(new_entry_frame)
        self.new_entry_website.grid(row=1, column=0, padx=10, pady=1)

        new_entry_username_label = ctk.CTkLabel(new_entry_frame, text="Username:")
        new_entry_username_label.grid(row=0, column=1, padx=10, pady=1)
        self.new_entry_username = ctk.CTkEntry(new_entry_frame)
        self.new_entry_username.grid(row=1, column=1, padx=10, pady=1)
        
        new_entry_password_label = ctk.CTkLabel(new_entry_frame, text="Password:")
        new_entry_password_label.grid(row=0, column=2, padx=10, pady=1)        
        self.new_entry_password = ctk.CTkEntry(new_entry_frame, show="*")
        self.new_entry_password.grid(row=1, column=2, padx=10, pady=1)

        self.new_entry_add = ctk.CTkButton(new_entry_frame, text="Add New", command=self.add_new_password)
        self.new_entry_add.grid(row=1, column=3, padx=10, pady=1)
        
        self.vault_display_frame = ctk.CTkFrame(self.app_frame)
        self.vault_display_frame.grid(row=2, column=0, padx=20, pady=5, sticky="nsew")

        self.entries_container = ctk.CTkScrollableFrame(self.app_frame, height=265)
        self.entries_container.grid(row=2, column=0, padx=20, pady=5, sticky="nsew")
        self.load_passwords()
        
    def add_new_password(self):
        website = self.new_entry_website.get().strip()
        username = self.new_entry_username.get().strip()
        password = self.new_entry_password.get().strip()

        if not all([website, username, password]):
            messagebox.showerror("Error", "All fields are required.")
            return

        try:
            self.password_manager.add_password_record(website, username, password)
            messagebox.showinfo("Success", "Password added successfully!")
            self.new_entry_website.delete(0, 'end')
            self.new_entry_username.delete(0, 'end')
            self.new_entry_password.delete(0, 'end')
            self.load_passwords()
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to add password: {e}")
                   
    def load_passwords(self):
        for widget in self.entries_container.winfo_children():
            widget.destroy()

        entries = self.password_manager.get_all_passwords_for_user()
        for idx, entry in enumerate(entries):
            record_id, website, username, password = entry
            entry_frame = ctk.CTkFrame(self.entries_container)
            entry_frame.grid(row=idx, column=0, padx=5, pady=5, sticky="ew")

            website_label = ctk.CTkLabel(entry_frame, text=website, width=130)
            website_label.grid(row=0, column=0, padx=10)
            username_label = ctk.CTkLabel(entry_frame, text=username, width=130)
            username_label.grid(row=0, column=1, padx=10)
            password_label = ctk.CTkLabel(entry_frame, text=password, width=130)
            password_label.grid(row=0, column=2, padx=10)
            
            copy_btn = ctk.CTkButton(entry_frame, text="Copy", width=20, command=lambda pwd=password: self.copy_password(pwd))
            copy_btn.grid(row=0, column=3, padx=5)

            edit_btn = ctk.CTkButton(entry_frame, text="Edit", width= 20, command=lambda id=record_id: self.edit_password(id))
            edit_btn.grid(row=0, column=4, padx=5)

            del_btn = ctk.CTkButton(entry_frame, text="Delete", width= 20, command=lambda id=record_id: self.delete_password(id))
            del_btn.grid(row=0, column=5, padx=5)
     
    def copy_password(self, password):
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def edit_password(self, record_id):
        pass
    
    def delete_password(self, record_id):
        try:
            self.password_manager.delete_password_record(record_id)
            self.load_passwords()  # Refresh the list of passwords
            messagebox.showinfo("Success", "Password deleted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete password: {e}")



        
    def open_secure_notes(self):
        # Placeholder for Secure Notes functionality
        print("Opening Secure Notes")

    def logout(self, frame):
        frame.destroy()
        # Properly close the database connection or any other cleanup
        self.db_connection.close()
        self.initial_frame() 
        
