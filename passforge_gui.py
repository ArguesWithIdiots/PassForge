# Basic imports

import tkinter as tk
from tkinter import ttk, messagebox
from passforge import generate_password

# Definitions

def create_app():
    root = tk.Tk()
    root.title("PassForge - Password Generator")
    root.resizable(False, False)

    # Main container frame
    main_frame = ttk.Frame(root, padding=20)
    main_frame.grid(row=0, column=0, sticky="NSEW")

    # Configure grid (future expansion maybe)

    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    # Row 0

    length_label = ttk.Label(main_frame, text="Password Length:")
    length_label.grid(row=0, column=0, sticky="W")
    length_var = tk.StringVar(value="16") #default
    length_entry = ttk.Entry(main_frame, textvariable=length_var, width=10)
    length_entry.grid(row=0, column=1, sticky="W", padx=(5, 0))

    # Row 1-3: Checkboxes

    use_upper_var = tk.BooleanVar(value=True)
    use_numbers_var = tk.BooleanVar(value=True)
    use_special_var = tk.BooleanVar(value=True)

    upper_check = ttk.Checkbutton(
        main_frame, text="Include uppercase", variable=use_upper_var
    )
    upper_check.grid(row=1, column=0, columnspan=2, sticky="W", pady=(0, 0))

    numbers_check = ttk.Checkbutton(
        main_frame, text="Include numbers", variable=use_numbers_var
    )
    numbers_check.grid(row=2, column=0, columnspan=2, sticky="W", pady=(0, 0))

    special_check = ttk.Checkbutton(
        main_frame, text="Include special characters", variable=use_special_var
    )
    special_check.grid(row=3, column=0, columnspan=2, sticky="W", pady=(0, 0))

    # Row 4: Generate button
    generate_button = ttk.Button(
        main_frame,
        text="Generate password",
        command=lambda: on_generate_click(
            length_var,
            use_upper_var,
            use_numbers_var,
            use_special_var,
            password_var
        ),
    )
    generate_button.grid(row=4, column=0, columnspan=2, pady=(15,5), sticky="EW")

    #Row 5: Password display
    password_label = ttk.Label(main_frame, text="Generated password:")
    password_label.grid(row=5, column=0, sticky="W", pady=(10, 0))

    password_var = tk.StringVar()
    password_entry = ttk.Entry(
        main_frame, textvariable=password_var, width=40, state="readonly"
    )
    password_entry.grid(row=6, column=0, columnspan=2, sticky="EW")

    # Row 7: Copy button
    copy_button = ttk.Button(
        main_frame,
        text="Copy to clipboard",
        command=lambda: on_copy_click(root, password_var),
    )
    copy_button.grid(row=7, column=0, columnspan=2, pady=(10,0), sticky="EW")

    return root

# Button handlers
def on_generate_click(length_var, use_upper_var, use_numbers_var, use_special_var, password_var):
    raw_length = length_var.get().strip()

    try:
        length = int(raw_length)
        if length < 8:
            raise ValueError("Length must be at least 8.")
    except ValueError:
        messagebox.showerror("Invalid length", "Please enter a valid length")
        return
    
    try:
        password = generate_password(
            length=length,
            use_upper=use_upper_var.get(),
            use_numbers=use_numbers_var.get(),
            use_special=use_special_var.get(),
        )
    except ValueError as e:
        messagebox.showerror("Error", str(e))
        return
    
    password_var.set(password)

def on_copy_click(root, password_var):
    password = password_var.get()
    if not password:
        messagebox.showerror("Nothing to copy", "Generate a password first")
        return
    
    root.clipboard_clear()
    root.clipboard_append(password)
    messagebox.showinfo("Copied", "Password copied to clipboard")
    
if __name__ == "__main__":
    app = create_app()
    app.mainloop()