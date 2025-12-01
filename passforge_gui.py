# Basic imports

import tkinter as tk
from tkinter import ttk, messagebox
from passforge import generate_password

# Definitions

def create_app():
    root = tk.Tk()
    root.title("PassForge - Password Generator")
    root.resizable(False, False)
    # Optional: enforce a minimum window size if it looks cramped
    # root.minsize(350, 220)

    # Main container frame
    main_frame = ttk.Frame(root, padding=20)
    main_frame.grid(row=0, column=0, sticky="NSEW")

    # Configure grid
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    # Row 0–1: Length label + entry + slider 

    length_label = ttk.Label(main_frame, text="Password length (8–30):")
    length_label.grid(row=0, column=0, sticky="W")

    # Shared IntVar representing the "canonical" length value
    length_var = tk.IntVar(value=16)

    # Entry for direct typing
    length_entry = ttk.Entry(main_frame, textvariable=length_var, width=6)
    length_entry.grid(row=0, column=1, sticky="W", padx=(5, 0))

    # We'll define handlers that can see length_var, length_entry, length_slider
    def on_slider_change(value: str) -> None:
        """Called whenever the slider is moved."""
        try:
            value_int = int(round(float(value)))
        except ValueError:
            return
        # Clamp to 8–30
        if value_int < 8:
            value_int = 8
        elif value_int > 30:
            value_int = 30
        length_var.set(value_int)

    def on_length_entry_change(event=None) -> None:
        """Called when the user finishes editing the entry."""
        text = length_entry.get().strip()
        try:
            value = int(text)
        except ValueError:
            # Revert to current valid value
            value = length_var.get()

        # Clamp to 8–30
        if value < 8:
            value = 8
        elif value > 30:
            value = 30

        length_var.set(value)
        length_slider.set(value)

    # Slider for choosing length between 8 and 30
    length_slider = ttk.Scale(
        main_frame,
        from_=8,
        to=30,
        orient="horizontal",
        command=on_slider_change,
    )
    length_slider.grid(row=1, column=0, columnspan=2, sticky="EW", pady=(5, 10))

    # Bind entry so manual edits get clamped and sync the slider
    length_entry.bind("<FocusOut>", on_length_entry_change)
    length_entry.bind("<Return>", on_length_entry_change)

    # Row 2–4: Checkboxes 

    use_upper_var = tk.BooleanVar(value=True)
    use_numbers_var = tk.BooleanVar(value=True)
    use_special_var = tk.BooleanVar(value=True)

    upper_check = ttk.Checkbutton(
        main_frame, text="Include uppercase", variable=use_upper_var
    )
    upper_check.grid(row=2, column=0, columnspan=2, sticky="W", pady=(10, 0))

    numbers_check = ttk.Checkbutton(
        main_frame, text="Include numbers", variable=use_numbers_var
    )
    numbers_check.grid(row=3, column=0, columnspan=2, sticky="W")

    special_check = ttk.Checkbutton(
        main_frame, text="Include special characters", variable=use_special_var
    )
    special_check.grid(row=4, column=0, columnspan=2, sticky="W", pady=(0, 10))

    # Row 5–6: Password display 

    password_label = ttk.Label(main_frame, text="Generated password:")
    password_label.grid(row=5, column=0, sticky="W", pady=(0, 0))

    password_var = tk.StringVar()
    password_entry = ttk.Entry(
        main_frame, textvariable=password_var, width=40, state="readonly"
    )
    password_entry.grid(row=6, column=0, columnspan=2, sticky="EW")

    # Row 7: Generate button 

    generate_button = ttk.Button(
        main_frame,
        text="Generate password",
        command=lambda: on_generate_click(
            length_var,
            use_upper_var,
            use_numbers_var,
            use_special_var,
            password_var,
        ),
    )
    generate_button.grid(row=7, column=0, columnspan=2, pady=(15, 5), sticky="EW")

    # Row 8: Copy button 

    copy_button = ttk.Button(
        main_frame,
        text="Copy to clipboard",
        command=lambda: on_copy_click(root, password_var),
    )
    copy_button.grid(row=8, column=0, columnspan=2, pady=(5, 0), sticky="EW")

    return root



# Button handlers
def on_generate_click(length_var, use_upper_var, use_numbers_var, use_special_var, password_var):
    """Handle the Generate button click."""
    try:
        length = int(length_var.get())
    except (TypeError, ValueError):
        messagebox.showerror("Invalid length", "Please enter a valid number.")
        return

    if length < 8 or length > 30:
        messagebox.showerror("Invalid length", "Length must be between 8 and 30.")
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