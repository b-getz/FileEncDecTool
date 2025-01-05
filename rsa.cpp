#include "rsa.h"
#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;

void generateRSAKeys(const string& publicKeyFile, const string& privateKeyFile) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        cerr << "Error creating context: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        return;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        cerr << "Error generating RSA keys: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    EVP_PKEY_CTX_free(ctx);

    // Save public key
    FILE* pubFile = fopen(publicKeyFile.c_str(), "wb");
    if (!pubFile || PEM_write_PUBKEY(pubFile, pkey) <= 0) {
        cerr << "Error saving public key: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        fclose(pubFile);
        EVP_PKEY_free(pkey);
        return;
    }
    fclose(pubFile);

    // Save private key
    FILE* privFile = fopen(privateKeyFile.c_str(), "wb");
    if (!privFile || PEM_write_PrivateKey(privFile, pkey, NULL, NULL, 0, NULL, NULL) <= 0) {
        cerr << "Error saving private key: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        fclose(privFile);
        EVP_PKEY_free(pkey);
        return;
    }
    fclose(privFile);

    EVP_PKEY_free(pkey);
    cout << "RSA keys generated successfully." << endl;
}

void rsaEncrypt(const string& inputFile, const string& outputFile, const string& publicKeyFile) {
    FILE* pubFile = fopen(publicKeyFile.c_str(), "rb");
    if (!pubFile) {
        cerr << "Error opening public key file." << endl;
        return;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(pubFile, NULL, NULL, NULL);
    fclose(pubFile);
    if (!pkey) {
        cerr << "Error reading public key: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        return;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        cerr << "Error initializing encryption: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        EVP_PKEY_free(pkey);
        return;
    }

    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);
    if (!in || !out) {
        cerr << "Error opening files for encryption." << endl;
        EVP_PKEY_free(pkey);
        return;
    }

    string plaintext((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    size_t outLen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outLen, (unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) {
        cerr << "Error determining encrypted size: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return;
    }

    unsigned char* encrypted = new unsigned char[outLen];
    if (EVP_PKEY_encrypt(ctx, encrypted, &outLen, (unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) {
        cerr << "Encryption error: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        delete[] encrypted;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return;
    }

    out.write((char*)encrypted, outLen);
    cout << "File encrypted successfully." << endl;

    delete[] encrypted;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

void rsaDecrypt(const string& inputFile, const string& outputFile, const string& privateKeyFile) {
    FILE* privFile = fopen(privateKeyFile.c_str(), "rb");
    if (!privFile) {
        cerr << "Error opening private key file." << endl;
        return;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(privFile, NULL, NULL, NULL);
    fclose(privFile);
    if (!pkey) {
        cerr << "Error reading private key: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        return;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
        cerr << "Error initializing decryption: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        EVP_PKEY_free(pkey);
        return;
    }

    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);
    if (!in || !out) {
        cerr << "Error opening files for decryption." << endl;
        EVP_PKEY_free(pkey);
        return;
    }

    string encrypted((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    size_t outLen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outLen, (unsigned char*)encrypted.c_str(), encrypted.size()) <= 0) {
        cerr << "Error determining decrypted size: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return;
    }

    unsigned char* decrypted = new unsigned char[outLen];
    if (EVP_PKEY_decrypt(ctx, decrypted, &outLen, (unsigned char*)encrypted.c_str(), encrypted.size()) <= 0) {
        cerr << "Decryption error: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        delete[] decrypted;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return;
    }

    out.write((char*)decrypted, outLen);
    cout << "File decrypted successfully." << endl;

    delete[] decrypted;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

