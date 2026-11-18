

#   Run with py file_encryptor.py  command in terminal

from cryptography.fernet import Fernet

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()



def encrypt_file(filename):
    key = load_key()
    f = Fernet(key)

    with open(filename, "rb") as file:
        data = file.read()

    encrypted_data = f.encrypt(data)

    with open(filename, "wb") as file:
        file.write(encrypted_data)

    print("File Encrypted 🔒")




def decrypt_file(filename):
    key = load_key()
    f = Fernet(key)

    with open(filename, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = f.decrypt(encrypted_data)

    with open(filename, "wb") as file:
        file.write(decrypted_data)

    print("File Decrypted 🔓")




print("🔐 File Encryption Tool")
print("1. Generate Key")
print("2. Encrypt File")
print("3. Decrypt File")

choice = input("Enter your choice: ")

if choice == "1":
    generate_key()

elif choice == "2":
    file = input("Enter filename: ")
    encrypt_file(file)

elif choice == "3":
    file = input("Enter filename: ")
    decrypt_file(file)

else:
    print("Invalid choice")