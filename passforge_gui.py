# Basic imports

import tkinter as tk
from tkinter import ttk, messagebox
from passforge import generate_password
import string
import math

# Similar color constants for dark/light
DARK_BG = "#1e1e1e"
DARK_FG = "#f5f5f5"
DARK_ACCENT = "#2b2b2b"
LIGHT_LISTBOX_BG = "white"
LIGHT_LISTBOX_FG = "black"

# Strength meter colors
STRENGTH_WEAK = "#ff4d4d"        # red
STRENGTH_MEDIUM = "#ff9933"      # orange
STRENGTH_STRONG = "#ffeb3b"      # yellow
STRENGTH_VERY_STRONG = "#4caf50" # green
STRENGTH_EXTREME = "#9c27b0"     # blue
STRENGTH_NEUTRAL = "#cccccc"     # default/unknown

# Definitions

def create_app():
    root = tk.Tk()
    root.title("PassForge - Password Generator")
    root.resizable(False, False)

    # Main container frame
    main_frame = ttk.Frame(root, padding=20)
    main_frame.grid(row=0, column=0, sticky="NSEW")

    # Configure grid
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    # ttk style object for theming
    style = ttk.Style(root)
    default_theme = style.theme_use()

    # Row 0–1: Length label + entry + slider 

    length_label = ttk.Label(main_frame, text="Password length (8–30):")
    length_label.grid(row=0, column=0, sticky="W")

    # Shared IntVar representing the "canonical" length value
    length_var = tk.IntVar(value=16)

    # Entry for direct typing
    length_entry = ttk.Entry(main_frame, textvariable=length_var, width=6)
    length_entry.grid(row=0, column=1, sticky="W", padx=(5, 0))

    # Handlers that can see length_var, length_entry, length_slider
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
        update_strength_meter()

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
        update_strength_meter()

    # Slider for choosing length between 8 and 30
    length_slider = ttk.Scale(
        main_frame,
        from_=8,
        to=30,
        orient="horizontal",
        command=on_slider_change,
    )
    length_slider.grid(row=1, column=0, columnspan=2, sticky="EW", pady=(5, 10))

    # Strength meter (label + colored bar)
    strength_text_label = ttk.Label(
        main_frame, 
        text="Strength: (not calculated)",
        width=22 # prevents resizing
    )
    strength_text_label.grid(row=2, column=0, sticky="W")

    strength_bar = tk.Frame(
        main_frame,
        height=10,
        width=120,
        bg=STRENGTH_NEUTRAL,
    )
    strength_bar.grid(row=2, column=1, sticky="EW", pady=(0, 5))
    strength_bar.grid_propagate(False)

    # Bind entry so manual edits get clamped and sync the slider
    length_entry.bind("<FocusOut>", on_length_entry_change)
    length_entry.bind("<Return>", on_length_entry_change)

    def update_strength_meter():
        """Update strength label/bar based on length and selected character sets."""
        try:
            length = int(length_var.get())
        except (TypeError, ValueError):
            length = 0

        if length <= 0:
            strength_text_label.configure(text="Strength: (not calculated)")
            strength_bar.configure(bg=STRENGTH_NEUTRAL)
            return

        # Base charset: lowercase is always included by PassForge
        charset_size = 26  # ascii_lowercase
        if use_upper_var.get():
            charset_size += 26
        if use_numbers_var.get():
            charset_size += 10
        if use_special_var.get():
            charset_size += len(string.punctuation)

        if charset_size <= 0:
            strength_text_label.configure(text="Strength: (not calculated)")
            strength_bar.configure(bg=STRENGTH_NEUTRAL)
            return

        # Entropy in bits, but we only expose qualitative strength
        entropy = length * math.log2(charset_size)

        # Map entropy → label + color
        if entropy < 40:
            label = "Weak"
            color = STRENGTH_WEAK
        elif entropy < 60:
            label = "Medium"
            color = STRENGTH_MEDIUM
        elif entropy < 80:
            label = "Strong"
            color = STRENGTH_STRONG
        elif entropy < 110:
            label = "Very strong"
            color = STRENGTH_VERY_STRONG
        else:
            label = "Extreme"
            color = STRENGTH_EXTREME

        strength_text_label.configure(text=f"Strength: {label}")
        strength_bar.configure(bg=color)

    # Row 2: Number of passwords dropdown (1–10)

    count_label = ttk.Label(main_frame, text="Number of passwords:")
    count_label.grid(row=3, column=0, sticky="W", pady=(0, 5))

    count_var = tk.StringVar(value="1")
    count_combo = ttk.Combobox(
        main_frame,
        textvariable=count_var,
        values=[str(i) for i in range(1, 11)],
        state="readonly",
        width=5,
    )
    count_combo.grid(row=3, column=1, sticky="W", pady=(0, 5))

    # Row 3–5: Checkboxes 

    use_upper_var = tk.BooleanVar(value=True)
    use_numbers_var = tk.BooleanVar(value=True)
    use_special_var = tk.BooleanVar(value=True)

    upper_check = ttk.Checkbutton(
        main_frame, text="Include uppercase", variable=use_upper_var, command=update_strength_meter,
    )
    upper_check.grid(row=4, column=0, columnspan=2, sticky="W", pady=(10, 0))

    numbers_check = ttk.Checkbutton(
        main_frame, text="Include numbers", variable=use_numbers_var, command=update_strength_meter,
    )
    numbers_check.grid(row=5, column=0, columnspan=2, sticky="W")

    special_check = ttk.Checkbutton(
        main_frame, text="Include special characters", variable=use_special_var, command=update_strength_meter,
    )
    special_check.grid(row=6, column=0, columnspan=2, sticky="W", pady=(0, 10))

    # Row 6–7: Password display (Listbox)

    password_label = ttk.Label(main_frame, text="Generated password(s):")
    password_label.grid(row=7, column=0, columnspan=2, sticky="W", pady=(0, 0))

    # Listbox to display 1–10 passwords, one per row
    password_listbox = tk.Listbox(
        main_frame,
        width=40,
        height=1,          # will be adjusted dynamically
        exportselection=False,  # keep selection independent
    )
    password_listbox.grid(row=8, column=0, columnspan=2, sticky="EW")

        # Dark mode state
    dark_mode_var = tk.BooleanVar(value=False)

    def set_dark_mode(dark: bool):
        """Apply light or dark theme."""
        if dark:
            # Use a theme that respects custom colors
            style.theme_use("clam")

            # Define dark styles
            style.configure("Dark.TFrame", background=DARK_BG)
            style.configure("Dark.TLabel", background=DARK_BG, foreground=DARK_FG)
            style.configure("Dark.TCheckbutton", background=DARK_BG, foreground=DARK_FG)
            style.configure("Dark.TButton", background=DARK_ACCENT, foreground=DARK_FG)
            style.map("Dark.TButton", background=[("active", "#3a3a3a")])

            # Apply styles
            root.configure(bg=DARK_BG)
            main_frame.configure(style="Dark.TFrame")

            for lbl in (length_label, count_label, password_label, strength_text_label):
                lbl.configure(style="Dark.TLabel")

            for chk in (upper_check, numbers_check, special_check, dark_toggle):
                chk.configure(style="Dark.TCheckbutton")

            for btn in (generate_button, copy_button):
                btn.configure(style="Dark.TButton")

            # Listbox (non-ttk widget)
            password_listbox.configure(
                bg=DARK_ACCENT,
                fg=DARK_FG,
                selectbackground="#555555",
                selectforeground=DARK_FG,
                highlightthickness=0,
                borderwidth=0,
            )

        else:
            # Restore original platform theme
            style.theme_use(default_theme)

            root.configure(bg="")
            main_frame.configure(style="TFrame")

            # Return widgets to default ttk styles
            for lbl in (length_label, count_label, password_label, strength_text_label):
                lbl.configure(style="TLabel")

            for chk in (upper_check, numbers_check, special_check, dark_toggle):
                chk.configure(style="TCheckbutton")

            for btn in (generate_button, copy_button):
                btn.configure(style="TButton")

            password_listbox.configure(
                bg=LIGHT_LISTBOX_BG,
                fg=LIGHT_LISTBOX_FG,
                selectbackground="#c0c0ff",
                selectforeground="black",
                highlightthickness=1,
                borderwidth=1,
            )

    # Row 8: Generate button 

    generate_button = ttk.Button(
        main_frame,
        text="Generate password(s)",
        command=lambda: on_generate_click(
            length_var,
            use_upper_var,
            use_numbers_var,
            use_special_var,
            count_var,
            password_listbox,
        ),
    )
    generate_button.grid(row=9, column=0, columnspan=2, pady=(15, 5), sticky="EW")

    # Row 9: Copy button 

    copy_button = ttk.Button(
        main_frame,
        text="Copy selected password",
        command=lambda: on_copy_click(root, password_listbox),
    )
    copy_button.grid(row=10, column=0, columnspan=2, pady=(5, 0), sticky="EW")

        # Dark mode toggle
    dark_toggle = ttk.Checkbutton(
        main_frame,
        text="Dark mode",
        variable=dark_mode_var,
        command=lambda: set_dark_mode(dark_mode_var.get()),
    )
    dark_toggle.grid(row=11, column=0, columnspan=2, pady=(8, 0), sticky="W")

# Start in light mode once everything is created
    set_dark_mode(False)
    update_strength_meter()

# Lock the initial window size so labels changing text don't cause a resize
    root.update_idletasks()
    root.minsize(root.winfo_width(), root.winfo_height())

    return root



# Button handlers
def on_generate_click(length_var,
                      use_upper_var,
                      use_numbers_var,
                      use_special_var,
                      count_var,
                      password_listbox):
    """Handle the Generate button click."""
    # Length validation
    try:
        length = int(length_var.get())
    except (TypeError, ValueError):
        messagebox.showerror("Invalid length", "Please enter a valid number.")
        return

    if length < 8 or length > 30:
        messagebox.showerror("Invalid length", "Length must be between 8 and 30.")
        return

    # Count validation (1–10)
    try:
        count = int(count_var.get())
    except (TypeError, ValueError):
        count = 1

    if count < 1:
        count = 1
    elif count > 10:
        count = 10

    # Generate passwords
    passwords = []
    try:
        for _ in range(count):
            pwd = generate_password(
                length=length,
                use_upper=use_upper_var.get(),
                use_numbers=use_numbers_var.get(),
                use_special=use_special_var.get(),
            )
            passwords.append(pwd)
    except ValueError as e:
        messagebox.showerror("Error", str(e))
        return

    # Display them in the listbox (one per row)
    password_listbox.delete(0, "end")
    for pwd in passwords:
        password_listbox.insert("end", pwd)

    # Adjust the visible height to match the number of passwords (1–10)
    password_listbox.config(height=count)


def on_copy_click(root, password_listbox):
    # Copy only the selected password
    selection = password_listbox.curselection()
    if not selection:
        messagebox.showerror("Nothing selected", "Select a password to copy.")
        return

    index = selection[0]
    password = password_listbox.get(index)

    if not password:
        messagebox.showerror("Nothing to copy", "Generate a password first.")
        return
    
    root.clipboard_clear()
    root.clipboard_append(password)
    messagebox.showinfo("Copied", "Password copied to clipboard")
    

if __name__ == "__main__":
    app = create_app()
    app.mainloop()
