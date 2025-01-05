#include <iostream>
#include <string>
#include "aes.h"
#include <openssl/rand.h>

using namespace std;

void performAES() {
    string inputFile, outputFile, keyHex, ivHex;
    unsigned char key[32], iv[16];
    int operation;

    cout << "\nAES Operations:" << endl;
    cout << "1. Encrypt a file" << endl;
    cout << "2. Decrypt a file" << endl;
    cout << "Enter choice (1-2): ";
    cin >> operation;

    if (operation == 1) {
        cout << "Enter the input file name: ";
        cin >> inputFile;
        cout << "Enter the output file name: ";
        cin >> outputFile;

        if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
            cout << "Error generating random KEY/IV." << endl;
            return;
        }

        encAES(inputFile, outputFile, key, iv);

        cout << "KEY (IMPORTANT: Save this): ";
        for (int i = 0; i < sizeof(key); i++) printf("%02x", key[i]);
        cout << endl;

        cout << "IV (Initialization Vector): ";
        for (int i = 0; i < sizeof(iv); i++) printf("%02x", iv[i]);
        cout << endl;

    } else if (operation == 2) {
        cout << "Enter the encrypted file name: ";
        cin >> inputFile;
        cout << "Enter the output file name: ";
        cin >> outputFile;

        cout << "Enter the KEY (hex): ";
        cin >> keyHex;
        cout << "Enter the IV (hex): ";
        cin >> ivHex;

        for (size_t i = 0; i < sizeof(key); i++) {
            sscanf(keyHex.c_str() + 2 * i, "%2hhx", &key[i]);
        }
        for (size_t i = 0; i < sizeof(iv); i++) {
            sscanf(ivHex.c_str() + 2 * i, "%2hhx", &iv[i]);
        }

        decAES(inputFile, outputFile, key, iv);
    } else {
        cout << "Invalid choice. Returning to the main menu." << endl;
    }
}

void showMenu() {
    cout << "File Enc & Dec Tool" << endl;
    cout << "___________________" << endl;
    cout << "1. AES" << endl;
    cout << "2. RSA" << endl;
    cout << "3. Exit" << endl;
    cout << "\nEnter Your Choice (1-3): ";
}

int main() {
    int choice;

    while (true) {
        showMenu();
        cin >> choice;

        switch (choice) {
            case 1:
                cout << "\nYou have selected AES." << endl;
                performAES();
                break;
            case 2:
                cout << "\nYou have selected RSA." << endl;
                break;
            case 3:
                cout << "\nExiting the program..." << endl;
                return 0;
            default:
                cout << "\nInvalid choice. Please enter a new choice." << endl;
        }
    }

    return 0;
}

