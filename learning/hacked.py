import os
import hashlib

# Set the path to the local file that will store the shadow file contents
LOCAL_FILE = 'shadow_backup.txt'

def read_shadow_file():
    try:
        with open('/etc/shadow', 'r') as f:
            contents = f.read()
            return contents
    except PermissionError:
        print("Error: Permission denied. You need root privileges to access /etc/shadow")
        return None

def store_shadow_file(contents):
    with open(LOCAL_FILE, 'w') as f:
        f.write(contents)

def check_for_changes():
    current_contents = read_shadow_file()
    if current_contents is None:
        return

    try:
        with open(LOCAL_FILE, 'r') as f:
            previous_contents = f.read()
    except FileNotFoundError:
        store_shadow_file(current_contents)
        print("Initial backup created.")
        return

    if current_contents != previous_contents:
        print("Changes detected!")
        print("New contents:")
        print(current_contents)
        store_shadow_file(current_contents)
    else:
        print("No changes detected.")

if __name__ == '__main__':
    check_for_changes()