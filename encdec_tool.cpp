#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace std;

/**
 * File Enc. and Dec. tool
 * 
 * This tool provides function to enc. and dec. files using AES-256.
 * It uses OpenSSL for operations.
 *
 * Features: 
 * - AES-256 in CBC mode
 * - Random IV & KEY  generation
 * - File-based
 *
 *   Author: Brandon Getz
 *   Date: 01/04/2025
 *   GitHub:
 */

// Function to perform AES enc on a file
void encAES(const string& inputFile, const string& outputFile, const unsigned char* key, const unsigned char* iv) {
	ifstream in(inputFile, ios::binary);
	ofstream out(outputFile, ios::binary);

	// Check if files were opened with success
	if (!in || !out) {
		cout << "Error: Unable to open files." << endl;
		return;
	}

	// Initialize context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
   	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    	unsigned char inBuffer[1024], outBuffer[1032];
    	int inLen, outLen;

	// Enc. the input file in chunks
    	while (in.read((char*)inBuffer, sizeof(inBuffer))) {
        	inLen = in.gcount();
        	EVP_EncryptUpdate(ctx, outBuffer, &outLen, inBuffer, inLen);
        	out.write((char*)outBuffer, outLen);
   	 }


	// Handle remaining
    	inLen = in.gcount();
    	EVP_EncryptUpdate(ctx, outBuffer, &outLen, inBuffer, inLen);
    	out.write((char*)outBuffer, outLen);
	
	// Finalize enc and write the last block
    	EVP_EncryptFinal_ex(ctx, outBuffer, &outLen);
    	out.write((char*)outBuffer, outLen);

	// Free the context
    	EVP_CIPHER_CTX_free(ctx);
    	cout << "Completed with success. Output saved to " << outputFile << endl;
}

// Main AES operation function
void performAES() {
	string inputFile, outputFile;
    	cout << "Enter the input file name: ";
    	cin >> inputFile;
    	cout << "Enter the output file name: ";
    	cin >> outputFile;

	// Generate random KEY and IV
    	unsigned char key[32], iv[16];
    	if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        	cout << "Error generating IV." << endl;
        	return;
   	 }

	// Call the enc function
    	encAES(inputFile, outputFile, key, iv);
	
	// Show the KEY and IV (used for dec. purposes)
   	cout << "KEY (IMPORTANT: Save this): ";
   	for (int i = 0; i < sizeof(key); i++) printf("%02x", key[i]);
   	cout << endl;

    	cout << "IV (Initialization Vector): ";
    	for (int i = 0; i < sizeof(iv); i++) printf("%02x", iv[i]);
    	cout << endl;
}

// Function to show user menu
void showMenu() {
	cout << "File Enc & Dec Tool" << endl;
	cout << "___________________" << endl;
	cout << "1. AES" << endl;
	cout << "2. RSA" << endl;
	cout << "3. Exit" << endl;
	cout << "\nEnter Your Choice (1-3): ";
}

// Main program loop
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

