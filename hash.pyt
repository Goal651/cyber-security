import hashlib

def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

def crack_md5_hash(hash_to_crack, dictionary_file):
    try:
        with open(dictionary_file, 'r', encoding='latin-1') as file:
            for line in file:
                word = line.strip()
                if md5_hash(word) == hash_to_crack:
                    return word
        return None
    except FileNotFoundError:
        print(f"Dictionary file '{dictionary_file}' not found.")
        return None

# MD5 hash to crack
hash_to_crack = '0094b4301235c109b9c741e5a1cb96ab'
# Path to the dictionary file
dictionary_file = 'rockyou.txt'

# Attempt to crack the hash
cracked_password = crack_md5_hash(hash_to_crack, dictionary_file)

if cracked_password:
    print(f"Hash cracked! The password is: {cracked_password}")
else:
    print("Failed to crack the hash.")
