import customtkinter as ctk
from ui import Application

def main():
    root = ctk.CTk()
    root.title("The Vault")
    root.geometry("680x400")
    app = Application(root)
    root.mainloop()

if __name__ == "__main__":
    main()

