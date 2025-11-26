# Shouldn't need anything else
import string
import secrets

# Basic parameters
def generate_password(length: int,
    use_upper: bool = True,
    use_numbers: bool = True,
    use_special: bool = True) -> str: 
    """
    Generate a secure random password...
    """
    if length < 8:
        raise ValueError("Password must be at least 8 characters.")

# Start with lowercase (always included)
    charset = list(string.ascii_lowercase)
    
    if use_upper:
        charset += list(string.ascii_uppercase)
    if use_numbers:
        charset += list(string.digits)
    if use_special:
        charset += list(string.punctuation)
    if not charset:
        raise ValueError("Character set is empty, enable at least one option.")

# Build the password one character at a time
    password = ''.join(secrets.choice(charset) for _ in range(length))

    return password

# Asking yes/no
def ask_yes_no(prompt: str) -> bool:
    """
    Ask a yes/no question in the terminal and return True or False.
    """
    while True:
        answer = input(prompt + " (y/n): ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please type y or n.")

# Main function
def main():
    print("===PassForge Simple Password Generator")

    # Ask for length and validate it's an integer >= 8
    while True:
        raw = input("Enter desired password length (ex: 12): ").strip()
        try:
            length = int(raw)
            if length < 8:
                print("Length must be at least 8.")
                continue
            break
        except ValueError:
            print("Please enter a valid number.")
    use_upper = ask_yes_no("Include uppercase letters?")
    use_numbers = ask_yes_no("Include numbers?")
    use_special = ask_yes_no("Include special characters?")
    # Generate the password
    try:
        password = generate_password(
            length=length,
            use_upper=use_upper,
            use_numbers=use_numbers,
            use_special=use_special,    
        )
    except ValueError as e:
        print(f"Error: {e}")
        return
    
    # Display the password
    print("\nYour generated password:")
    print(password)
    print("\nKeep it somewhere safe.")

if __name__ == "__main__":
    main()