import getpass
import os
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import InvalidToken

PRIVATE_KEY_FILE = "private_key.pem"

def get_random_filename():
    filename = str(uuid.uuid4())
    if not filename.endswith(".txt"):
        filename += ".txt"
    return filename

def save_decrypted_output_to_file(decrypted, filename):
    with open(filename, "w") as file:
        file.write(decrypted)

def generate_rsa_key_pair():
    passphrase = getpass.getpass("Enter a passphrase for the private key: ")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, passphrase

def save_private_key(private_key):
    with open(PRIVATE_KEY_FILE, "wb") as file:
        file.write(private_key)

def load_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as file:
        private_key = file.read()
    passphrase = getpass.getpass("Enter a passphrase for the private key: ")
    return private_key, passphrase

def encrypt(string, private_key):
    def pad(data, block_size):
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    public_key = private_key.public_key()
    symmetric_key = os.urandom(32)  # 32 bytes = 256 bits
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad the string before encryption
    padded_data = pad(string.encode('utf-8'), algorithms.AES.block_size)
    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data, encrypted_symmetric_key, iv

def decrypt(encrypted_data, encrypted_symmetric_key, iv, private_key):
    def remove_padding(data):
        padding_length = data[-1]
        return data[:-padding_length]

    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = remove_padding(decrypted_data_padded)
    return decrypted_data.decode()

def save_encrypted_data_to_file(encrypted, filename):
    with open(filename, "wb") as file:
        file.write(encrypted)

def encrypt_data(private_key):
    string_to_encrypt = input("Enter the string to encrypt: ")
    encrypted_data, encrypted_symmetric_key, iv = encrypt(string_to_encrypt, private_key)
    symmetric_key_hex = encrypted_symmetric_key.hex()
    print("Symmetric Key (Hex):", symmetric_key_hex)
    iv_hex = iv.hex()
    print("Initialization Vector (IV):", iv_hex)
    filename = get_random_filename()
    save_encrypted_data_to_file(encrypted_data, "encrypted_" + filename)
    filename = filename.strip()
    print("Encrypted data saved to", "encrypted_" + filename)
    save_encrypted_data_to_file(encrypted_symmetric_key, "key_" + filename)
    filename = filename.strip()
    print("Encrypted key saved to", "key_" + filename)

def decrypt_data(private_key):
    filename = input("Enter the file name for the encrypted data (without extension): ")
    filename = filename.strip()
    if not filename.endswith(".txt"):
        filename += ".txt"
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    iv_input = input("Enter the Initialization Vector (IV): ")
    iv = bytes.fromhex(iv_input)
    filename = input("Enter the file name for the encrypted symmetric key (without extension): ")
    filename = filename.strip()
    if not filename.endswith(".txt"):
        filename += ".txt"
    with open(filename, "rb") as file:
        encrypted_symmetric_key = file.read()
    decrypted = decrypt(encrypted_data, encrypted_symmetric_key, iv, private_key)
    print("Decrypted data:", decrypted)
    output_filename = get_random_filename()
    save_decrypted_output_to_file(decrypted, "decrypted_" + output_filename)
    print("Decrypted output saved to", "decrypted_" + output_filename)

def encrypt_decrypt_main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Stongly Encrypt Yours Data")
    # Check if the private key file exists
    if not os.path.exists(PRIVATE_KEY_FILE):
        print("Generate RSA key not found.")
        # Generate RSA key pair and save the private key
        private_key, passphrase = generate_rsa_key_pair()
        save_private_key(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        ))
        print("Generating a new key pair...")
    else:
        # Load the private key from the file
        private_key_pem, passphrase = load_private_key()
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=passphrase.encode(),
            backend=default_backend()
        )

    while True:
        action = input("Choose an action: (1) Encrypt, (2) Decrypt, (Q) Quit: ")
        if action == "1":
            encrypt_data(private_key)
        elif action == "2":
            decrypt_data(private_key)
        elif action.lower() == "q":
            #Clean up terminal output
            os.system('cls' if os.name == 'nt' else 'clear')
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please choose either '1' for encryption, '2' for decryption, or 'Q' to quit.")

try:
    encrypt_decrypt_main()
except NameError as e:
    print("Name error occurred:", str(e))
except ImportError as e:
    print("Failed to import required module(s):", str(e))
except InvalidToken as e:
    print("Invalid token:", str(e))
except FileNotFoundError as e:
    print("File not found:", str(e))
except Exception as e:
    print("An error occurred:", str(e))