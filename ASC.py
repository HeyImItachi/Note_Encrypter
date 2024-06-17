import sqlite3
from cryptography.fernet import Fernet
import hashlib
import hmac
import tkinter as tk
from tkinter import simpledialog
from tkinter import messagebox
import pyperclip  
from tkinter import ttk
from tkinter import Toplevel, Label, Entry, Button

# Function to generate or load an existing key
def load_or_generate_key():
    key_file = 'encryption.key'
    try:
        with open(key_file, 'rb') as file:
            key = file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as file:
            file.write(key)
    return key

key = load_or_generate_key()

# Create a connection to SQLite database
conn = sqlite3.connect('notes.db')

# Create a cursor
cursor = conn.cursor()

# Create table
cursor.execute('''CREATE TABLE IF NOT EXISTS notes
                (id INTEGER PRIMARY KEY, title TEXT, content TEXT)''')

# Function to encrypt a note and save it to the database
def encrypt_note(title, content):
    try:
        print(f"Inside encrypt_note: Title: {title}, Content: {content}")
        cipher_suite = Fernet(key)
        encrypted_text = cipher_suite.encrypt(content.encode())
        # Save the encrypted note to the database
        cursor.execute("INSERT INTO notes (title, content) VALUES (?, ?)", (title, encrypted_text))
        conn.commit()
        return encrypted_text
    except Exception as e:
        messagebox.showerror("Error", f"Failed to encrypt note: {e}")
        return None

# Function to decrypt a note
def decrypt_note(encrypted_content):
    try:
        cipher_suite = Fernet(key)
        decrypted_text = cipher_suite.decrypt(encrypted_content).decode()
        return decrypted_text
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt note: {e}")
        return None

# Tkinter GUI Implementation
class NotesApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw()  # Hide the main window initially
        self.login_window()  # Show the login window

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_login(self, username, password):
        # The expected username and hashed password
        expected_username = "Admin"
        expected_password_hash = hashlib.sha256("admin24".encode()).hexdigest()

        if username == expected_username and self.hash_password(password) == expected_password_hash:
            self.deiconify()  # Show the main window
            self.login.destroy()  # Close the login window
        else:
            messagebox.showerror("Login failed", "Incorrect username or password")

    def login_window(self):
        self.login = Toplevel(self)
        self.login.title("Login")
        self.login.geometry("300x150")

        Label(self.login, text="Username:").pack()
        username_entry = Entry(self.login)
        username_entry.pack()

        Label(self.login, text="Password:").pack()
        password_entry = Entry(self.login, show="*")
        password_entry.pack()

        Button(self.login, text="Login", command=lambda: self.check_login(username_entry.get(), password_entry.get())).pack()

        self.title('Secure Notes App')
        self.geometry('600x400')

        # Title Entry and Clear Button
        self.title_entry_frame = tk.Frame(self)
        self.title_entry_frame.pack(pady=10)

        self.title_label = tk.Label(self.title_entry_frame, text="Title:")
        self.title_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.title_entry = tk.Entry(self.title_entry_frame)
        self.title_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)

        self.clear_title_button = tk.Button(self.title_entry_frame, text="Clear", command=self.clear_title)
        self.clear_title_button.pack(side=tk.LEFT, padx=(10, 0))

        # Encrypt Note Button
        self.encrypt_button = tk.Button(self, text="Encrypt Note", command=self.encrypt_note_gui)
        self.encrypt_button.pack(pady=10)

        # Decrypt Note Button
        self.decrypt_button = tk.Button(self, text="Decrypt Note", command=self.decrypt_note_gui)
        self.decrypt_button.pack(pady=10)

        # Exit Button
        self.exit_button = tk.Button(self, text="Exit", command=self.quit_program)
        self.exit_button.pack(pady=10)

        # Treeview for displaying notes
        self.tree_frame = tk.Frame(self)
        self.tree_frame.pack(expand=True, fill='both')

        self.tree_scroll = tk.Scrollbar(self.tree_frame)
        self.tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(self.tree_frame, columns=("ID", "Title", "Content"), show="headings", yscrollcommand=self.tree_scroll.set)
        self.tree.heading("ID", text="ID")
        self.tree.heading("Title", text="Title")
        self.tree.heading("Content", text="Content")
        self.tree.pack(expand=True, fill='both')

        self.tree_scroll.config(command=self.tree.yview)

        # Context menu
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Delete", command=self.delete_note)
        self.menu.add_command(label="Copy Content", command=self.copy_content)  # Add this line

        # Bind the right-click event to the Treeview
        self.tree.bind("<Button-3>", self.show_context_menu)  # For Windows and Linux
        # For macOS, you might need to use "<Button-2>" instead of "<Button-3>"

        # Bind the double-click event to the Treeview
        self.tree.bind("<Double-1>", self.on_item_double_click)

        # Load the notes into the Treeview
        self.load_notes()

    def encrypt_note_gui(self):
        title = self.title_entry.get()
        encrypt_dialog = EncryptDialog(self)
        note = encrypt_dialog.show()
        # Check if note is None 
        if note is None:
            return  
        if note and title:
            print(f"Encrypting note: Title: {title}, Content: {note}")
            encrypted_note = encrypt_note(title, note)
            if encrypted_note:
                pyperclip.copy(encrypted_note.decode())  # Copy the encrypted note to clipboard
                messagebox.showinfo("Success", "Note encrypted successfully.\nThe encrypted note has been copied to the clipboard.")
                self.load_notes()  # Refresh the notes display
            else:
                messagebox.showerror("Error", "Failed to encrypt note.")
        else:
            messagebox.showerror("Error", "Title or note is empty.")

    def decrypt_note_gui(self):
        decrypt_dialog = DecryptDialog(self)
        encrypted_note = decrypt_dialog.show()
        if encrypted_note:
            decrypted_note = decrypt_note(encrypted_note.encode('utf-8'))
            if decrypted_note:
                pyperclip.copy(decrypted_note)  # Copy the decrypted note to clipboard
                messagebox.showinfo("Success", f"Decrypted Note: {decrypted_note}\nThe decrypted note has been copied to the clipboard.")
            else:
                messagebox.showerror("Error", "Failed to decrypt note.")

    def load_notes(self):
        # Remove existing rows
        for i in self.tree.get_children():
            self.tree.delete(i)
        # Query the database for notes
        cursor.execute("SELECT id, title, content FROM notes")
        for row in cursor.fetchall():
            self.tree.insert('', 'end', values=row)

    def on_item_double_click(self, event):
        # Get the selected item
        item_id = self.tree.selection()[0]
        item = self.tree.item(item_id)
        note_id = item['values'][0]

        # Fetch the title and encrypted content from the database using the note ID
        cursor.execute("SELECT title, content FROM notes WHERE id = ?", (note_id,))
        row = cursor.fetchone()
        title, encrypted_content = row

        # Decrypt the content
        decrypted_content = decrypt_note(encrypted_content)  

        if decrypted_content:
            # Display the title and decrypted content in a prompt message
            messagebox.showinfo(title, decrypted_content)
            # Copy the decrypted content to the clipboard
            pyperclip.copy(decrypted_content)
        else:
            messagebox.showerror("Error", "Failed to decrypt note.")

    def show_context_menu(self, event):
        try:
            # Display the context menu
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            # Make sure the menu is closed
            self.menu.grab_release()

    def delete_note(self):
        # Get the selected item
        selected_item = self.tree.selection()
        if selected_item:  # Make sure something is selected
            item_id = self.tree.item(selected_item)['values'][0]
            # Delete from database
            cursor.execute("DELETE FROM notes WHERE id = ?", (item_id,))
            conn.commit()
            # Delete from Treeview
            self.tree.delete(selected_item)

    def copy_content(self):
        # Get the selected item
        selected_item = self.tree.selection()
        if selected_item:  # Make sure something is selected
            item_id = self.tree.item(selected_item)['values'][0]
            # Fetch the encrypted content from the database using the note ID
            cursor.execute("SELECT content FROM notes WHERE id = ?", (item_id,))
            encrypted_content = cursor.fetchone()[0]
            # Copy the encrypted content to the clipboard
            pyperclip.copy(encrypted_content.decode())
            messagebox.showinfo("Success", "Encrypted content copied to clipboard.")

    def clear_title(self):
        """Clears the content of the title entry textbox."""
        self.title_entry.delete(0, tk.END)

    def quit_program(self):
        self.quit()

class EncryptDialog(Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Encrypt Note")
        self.geometry("400x300")  

        self.textbox = tk.Text(self, height=10, width=50)  # Larger textbox
        self.textbox.pack(padx=10, pady=10)

        self.clear_button = tk.Button(self, text="Clear", command=self.clear_text)
        self.clear_button.pack(side=tk.RIGHT, padx=10)

        self.submit_button = tk.Button(self, text="Encrypt", command=self.submit)
        self.submit_button.pack(side=tk.RIGHT)

        self.back_button = tk.Button(self, text="Back", command=self.destroy)
        self.back_button.pack(side=tk.LEFT, padx=10)

        self.result = None

    def clear_text(self):
        self.textbox.delete('1.0', tk.END)

    def submit(self):
        self.result = self.textbox.get('1.0', tk.END).strip()
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result

class DecryptDialog(Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Decrypt Note")
        self.geometry("400x300") 

        self.textbox = tk.Text(self, height=10, width=50)  # Larger textbox
        self.textbox.pack(padx=10, pady=10)

        self.clear_button = tk.Button(self, text="Clear", command=self.clear_text)
        self.clear_button.pack(side=tk.RIGHT, padx=10)

        self.submit_button = tk.Button(self, text="Decrypt", command=self.submit)
        self.submit_button.pack(side=tk.RIGHT)

        self.back_button = tk.Button(self, text="Back", command=self.destroy)
        self.back_button.pack(side=tk.LEFT, padx=10)
        
        self.result = None

    def clear_text(self):
        self.textbox.delete('1.0', tk.END)

    def submit(self):
        self.result = self.textbox.get('1.0', tk.END).strip()
        self.destroy()

    def show(self):
        self.wait_window()
        return self.result

if __name__ == "__main__":
    app = NotesApp()
    app.mainloop()