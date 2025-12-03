## UPDATE 4 — Multiple Password Generation + Select-to-Copy (December 3rd, 2025)
- Added a dropdown to generate up to 10 passwords at once.
- Passwords appear in a clean list with the program window expanding dynamically.
- Clicking "Copy selected password" copies only the highlighted one 
- Overall: cleaner UX, more control, less chaos.

## UPDATE 3 — Added synced length slider + input box (December 1st, 2025)
- Added a length slider (8–30 characters).
- Slider and input box are synced in real time, changing one updates the other.
- Manual entry is automatically clamped to the valid range.

## UPDATE 2 — GUI Added (November 2025)
- Added a Tkinter-based GUI (passforge_gui.py).
- Includes buttons, checkboxes, password display, and copy-to-clipboard.
- Successfully built a standalone Windows .exe using PyInstaller.
- Updated .gitignore so I don’t accidentally upload 900 MB of build trash.
- Basically, PassForge now has a “real app” mode and not just the gremlin CLI.

## UPDATE 1 — Initial CLI Version (November 2025)
- Created the main script (passforge.py).
- Added uppercase/number/special character toggles.
- Implemented basic input validation so it doesn’t explode instantly.
- Added packaging via pyproject.toml because pretending to be professional is fun.

# PassForge

A password generator that I wrote while learning Python.  
It works. I’m honestly as surprised as you are.

This little script asks you a few questions (like whether you want uppercase letters, numbers, special characters, etc.), and then spits out a randomly generated password. It uses Python’s `secrets` module, which is apparently “cryptographically secure.” I just trust the docs.

1. Why Does This Exist?

Because I wanted to put *something* on GitHub that wasn’t a half-finished tutorial or a “hello world” from 2021. Also because typing passwords manually is annoying, and I am supremely distrust of online password generators. I actually use this damn thing.

2. How to Use It

Open your terminal and run:

python passforge.py

or

py passforge.py

Windows is weird sometimes; one of them will work.

Then follow the prompts:

- Enter the length (minimum 8, probably not long enough) 
- Say yes/no to uppercase  
- Yes/no to numbers  
- Yes/no to special characters  
- Pray you remember the password after it prints it

Example output:

=== PassForge: Simple Password Generator ===
Enter desired password length (e.g., 10): 12
Include uppercase letters? (y/n): y
Include numbers? (y/n): y
Include special characters? (y/n): y

Your generated password:
#5v)B^39@cM!

If yours looks uglier, that’s normal.

3. What’s Inside

- A function that builds a character set  
- A function that generates a password  
- A function that harasses you until you type y or n  
- A `main()` function that ties it all together  
- Zero AI, zero machine learning, zero nonsense  
- Just Python. Like nature intended.

4. Things I Might Add Later

- Option to generate multiple passwords at once  
- CLI flags (so you can feel like a hacker)  
- Clipboard copier  
- Actual error handling instead of whatever this is  
- Tests… maybe… don’t hold your breath  

5. License

Do whatever you want with this. Seriously. If you can break it, improve it, or make it into something actually useful, go for it.
