#ifndef RSA_H
#define RSA_H

#include <string>

// Function declarations for RSA operations
void generateRSAKeys(const std::string& publicKeyFile, const std::string& privateKeyFile);
void rsaEncrypt(const std::string& inputFile, const std::string& outputFile, const std::string& publicKeyFile);
void rsaDecrypt(const std::string& inputFile, const std::string& outputFile, const std::string& privateKeyFile);

#endif // RSA_H

