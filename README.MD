# Strongly Encrypt Your Data

Strongly Encrypt Your Data is a Python program that allows you to encrypt and decrypt your sensitive data using the RSA encryption algorithm and AES symmetric encryption. This program provides a secure way to protect your data and ensure its confidentiality.

## Features

- Generate an RSA key pair and save the private key.
- Encrypt a string and save the encrypted data and symmetric key.
- Decrypt encrypted data using the corresponding symmetric key.

## Prerequisites

Before running the program, ensure you have the following prerequisites:

- Python 3.x installed on your system.
- The required Python packages installed:
  - cryptography
  - getpass

You can install the required packages using pip: pip install cryptography getpass

## Usage

1. Clone this repository or download the source code files.

2. Open a terminal or command prompt and navigate to the project directory.

3. Run the program by executing the following command: python hasher.py

4. Follow the prompts to choose the desired action: encryption or decryption.

5. If encrypting, enter the string to encrypt. The program will generate encrypted data and a symmetric key. It will save the encrypted data to a file, along with the encrypted symmetric key and initialization vector (IV).

6. If decrypting, provide the necessary input, such as the file name for the encrypted data, the IV, and the file name for the encrypted symmetric key. The program will decrypt the data and save the decrypted output to a file.

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! If you have any ideas, suggestions, or bug reports, please open an issue or submit a pull request.

## Disclaimer

Please note that this program is provided for educational and informational purposes only. It is your responsibility to ensure the proper usage and legality of encryption in your jurisdiction. The authors of this program are not liable for any misuse or illegal activities conducted using this program.



