# File Encryption and Decryption Tool
A C++ tool for secure file encryption and decryption, supporting both AES and RSA algorithms. This tool was built for educational purposes to gain a deeper understanding of crypotgraphic principles and real-world applications.

# Features
- **AES Encryption and Decryption**:
  - Implements AES-256 encryption in CBC mode.
  - Generates secure random keys and initialization vectors (IVs).
  - Encrypts files and decrypts them back to their original content using provided keys and IVs.
- **RSA Encryption and Decryption**:
  - Generates RSA public-private key pairs.
  - Encrypts files using the RSA public key and decrypts them using the private key.

# Setup Instructions & Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/b-getz/FileEncryptionTool.git
2. Navigate to the project folder:
   ```bash
   cd FileEncDecTool
3. Compile the program
   ```bash
   g++ -o encdec_tool aes.cpp rsa.cpp main.cpp -lssl -lcrypto
4. Run the program:
   ```bash
   ./encdec_tool
5. Select either the AES or RSA option from the menu
6. Choose the associated options
7. To exit, enter '3' or 'CTRL C'

# Testing Environment
This tool was built and tested in a Kali Linux virtual machine hosted in VirtualBox. It requires OpenSSL libraries (libssl-dev).

# Disclaimer
This tool is intended for **educational purposes** and should **ONLY** be used on owned files and data. Unauthorized use of this tool on sensitive or non-owned data could result in the violation of local laws and regulations.

# Future Enhancements
1. Enhanced User Interface
2. Support for larger files
