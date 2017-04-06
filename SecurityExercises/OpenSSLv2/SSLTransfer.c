#include "SSLTransfer.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

static void errorCheck(int ret)
{
	if (ret == -1)
	{
		perror(NULL);
		exit(1);
	}
}

static void keyedDigest(unsigned char* message, unsigned messageSize, unsigned char* hashBuff, const unsigned char* hashKey)
{
	HMAC_CTX* hmac_ctx;
	hmac_ctx = malloc(sizeof(HMAC_CTX));
	HMAC_CTX_init(hmac_ctx);

	HMAC_Init(hmac_init, hashKey, EVP_MD_size(EVP_md5()), EVP_md5());

	unsigned maxStepSize = 4;
	unsigned leftMessageSize = messageSize;

	while (leftMessageSize > 0)
	{
		unsigned stepSize = (leftMessageSize > maxStepSize) ? maxStepSize : leftMessageSize;
		HMAC_Update(hmac_ctx, message, stepSize);
		message += stepSize;
		leftMessageSize -= stepSize;
	}

	HMAC_Final(hmac_ctx, hashBuff, EVP_MD_size(EVP_md5()));

	HMAC_CTX_cleanup(hmac_ctx);
	free(hmac_ctx);
}

void encrypt(int sourceFD, int destinationFD, unsigned sourceByteCount, unsigned blocksPerStep, const unsigned char* encryptKey, const unsigned char* iv, const unsigned char* hashKey)
{
	// Encryption context
	EVP_CIPHER_CTX* encryptionCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(encryptionCtx);

	EVP_EncryptInit(encryptionCtx, EVP_aes_128_cbc(), encryptKey, iv);

	//Keyed hashing context
	HMAC_CTX* hmac_ctx;
	hmac_ctx = malloc(sizeof(HMAC_CTX));
	HMAC_CTX_init(hmac_ctx);

	HMAC_Init(hmac_init, hashKey, EVP_MD_size(EVP_md5()), EVP_md5());

	unsigned blockLength = 128 / 8;
	unsigned stepByteCount = blockLength * blocksPerStep;

	unsigned char plaintextStepBuffer[stepByteCount];
	unsigned char ciphertextStepBuffer[stepByteCount];
		
	unsigned stepCount = (sourceByteCount % stepByteCount == 0) ? sourceByteCount / stepByteCount : (sourceByteCount / stepByteCount) + 1;

	for (unsigned currentStep = 0; currentStep < stepCount; currentStep++)
	{
		int readByteCount = read(sourceFD, plaintextStepBuffer, stepByteCount);
		errorCheck(readByteCount);

		unsigned int outlength;
		EVP_EncryptUpdate(encryptionCtx, ciphertextStepBuffer, &outlength, plaintextStepBuffer, readByteCount);
		HMAC_Update(hmac_ctx, ciphertextStepBuffer, outlength);

		int writeByteCount = write(destinationFD, ciphertextStepBuffer, outlength);
		errorCheck(writeByteCount);

		writeByteCount = write(destinationFD, hmacBuffer, EVP_MD_size(EVP_md5()));
		errorCheck(writeByteCount);
	}

	unsigned int outlength;
	EVP_EncryptFinal(encryptionCtx, ciphertextStepBuffer, &outlength);
	HMAC_Update(hmac_ctx, ciphertextStepBuffer, outlength);

	unsigned char hmacBuffer[EVP_MD_size(EVP_md5())];
	HMAC_Final(hmac_ctx, hmacBuffer, EVP_MD_size(EVP_md5()));

	int ret = write(destinationFD, ciphertextStepBuffer, outlength);
	errorCheck(ret);

	ret = write(destinationFD, hmacBuffer, EVP_MD_size(EVP_md5()));
	errorCheck(ret);

	//Cleanup
	EVP_CIPHER_CTX_cleanup(encryptionCtx);
	free(encryptionCtx);
	
	HMAC_CTX_cleanup(hmac_ctx);
	free(hmac_ctx);
}

void decrypt(int sourceFD, int destinationFD, unsigned ciphertextBlockCount, unsigned blocksPerStep, const unsigned char* key, const unsigned char* iv)
{
	// Encryption context
	EVP_CIPHER_CTX* decryptionCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(decryptionCtx);

	EVP_DecryptInit(decryptionCtx, EVP_aes_128_cbc(), key, iv);

	//Keyed hashing context
	HMAC_CTX* hmac_ctx;
	hmac_ctx = malloc(sizeof(HMAC_CTX));
	HMAC_CTX_init(hmac_ctx);

	HMAC_Init(hmac_init, hashKey, EVP_MD_size(EVP_md5()), EVP_md5());

	unsigned blockLength = 128 / 8;
	unsigned stepByteCount = blockLength * blocksPerStep;

	unsigned char plaintextStepBuffer[stepByteCount];
	unsigned char ciphertextStepBuffer[stepByteCount];

	unsigned stepCount = (ciphertextBlockCount % blocksPerStep == 0 ) ? ciphertextBlockCount / blocksPerStep : (ciphertextBlockCount / blocksPerStep) + 1;

	for (unsigned step = 0; step < stepCount; step++)
	{
		int ciphertextReadByteCount = read(sourceFD, ciphertextStepBuffer, stepByteCount);
		errorCheck(ciphertextReadByteCount);

		HMAC_Update(hmac_ctx, ciphertextStepBuffer, ciphertextReadByteCount);

		unsigned int outlength;
		EVP_DecryptUpdate(decryptionCtx, plaintextStepBuffer, &outlength, ciphertextStepBuffer, ciphertextReadByteCount);

		int writeByteCount = (int) write(destinationFD, plaintextStepBuffer, outlength);
		errorCheck(writeByteCount);
	}

	unsigned int outlength;
	EVP_DecryptFinal(decryptionCtx, plaintextStepBuffer, &outlength);
	
	unsigned char hmacBuffer[EVP_MD_size(EVP_md5())];
	HMAC_Final(hmac_ctx, hmacBuffer, EVP_MD_size(EVP_md5()));
	
	unsigned char receivedHmacBuffer[]

	int writeByteCount = write(destinationFD, plaintextStepBuffer, outlength);
	errorCheck(writeByteCount);

	//Cleanup
	EVP_CIPHER_CTX_cleanup(decryptionCtx);
	free(decryptionCtx);

	HMAC_CTX_cleanup(hmac_ctx);
	free(hmac_ctx);
}