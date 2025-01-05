#ifndef AES_H
#define AES_H

#include <string>

// Function declarations for AES operations
void encAES(const std::string& inputFile, const std::string& outputFile, const unsigned char* key, const unsigned char* iv);
void decAES(const std::string& inputFile, const std::string& outputFile, const unsigned char* key, const unsigned char* iv);

#endif // AES_H

