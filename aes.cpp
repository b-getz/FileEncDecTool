#include "aes.h"
#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace std;

void encAES(const string& inputFile, const string& outputFile, const unsigned char* key, const unsigned char* iv) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    if (!in || !out) {
        cout << "Error: Unable to open files." << endl;
        return;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inBuffer[1024], outBuffer[1032];
    int inLen, outLen;

    while (in.read((char*)inBuffer, sizeof(inBuffer))) {
        inLen = in.gcount();
        EVP_EncryptUpdate(ctx, outBuffer, &outLen, inBuffer, inLen);
        out.write((char*)outBuffer, outLen);
    }

    inLen = in.gcount();
    EVP_EncryptUpdate(ctx, outBuffer, &outLen, inBuffer, inLen);
    out.write((char*)outBuffer, outLen);

    EVP_EncryptFinal_ex(ctx, outBuffer, &outLen);
    out.write((char*)outBuffer, outLen);

    EVP_CIPHER_CTX_free(ctx);
    cout << "Completed with success. Output saved to " << outputFile << endl;
}

void decAES(const string& inputFile, const string& outputFile, const unsigned char* key, const unsigned char* iv) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    if (!in || !out) {
        cout << "Error: Unable to open files." << endl;
        return;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inBuffer[1024], outBuffer[1032];
    int inLen, outLen;

    while (in.read((char*)inBuffer, sizeof(inBuffer))) {
        inLen = in.gcount();
        EVP_DecryptUpdate(ctx, outBuffer, &outLen, inBuffer, inLen);
        out.write((char*)outBuffer, outLen);
    }

    inLen = in.gcount();
    EVP_DecryptUpdate(ctx, outBuffer, &outLen, inBuffer, inLen);
    out.write((char*)outBuffer, outLen);

    if (EVP_DecryptFinal_ex(ctx, outBuffer, &outLen)) {
        out.write((char*)outBuffer, outLen);
        cout << "Completed with success. Output saved to " << outputFile << endl;
    } else {
        cout << "Error: Failure. Check the KEY and IV." << endl;
    }

    EVP_CIPHER_CTX_free(ctx);
}

