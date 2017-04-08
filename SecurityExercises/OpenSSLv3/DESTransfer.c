#include "DESTransfer.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <openssl/evp.h>

static void errorCheck(int ret)
{
	if (ret == -1)
	{
		perror(NULL);
		exit(1);
	}
}

void encrypt(int sourceFD, int destinationFD, unsigned sourceByteCount, unsigned blocksPerStep, const unsigned char* key, const unsigned char* iv)
{
	EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);

	EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);

	unsigned blockLength = 128 / 8;
	unsigned stepByteCount = blockLength * blocksPerStep;

	unsigned char plaintextStepBuffer[stepByteCount];
	unsigned char ciphertextStepBuffer[stepByteCount];
		
	unsigned stepCount = (sourceByteCount % stepByteCount == 0) ? sourceByteCount / stepByteCount : (sourceByteCount / stepByteCount) + 1;

	for (unsigned currentStep = 0; currentStep < stepCount; currentStep++)
	{
		int readByteCount = (int) read(sourceFD, plaintextStepBuffer, stepByteCount);
		errorCheck(readByteCount);

		int outlength;
		EVP_EncryptUpdate(ctx, ciphertextStepBuffer, &outlength, plaintextStepBuffer, readByteCount);

		int writeByteCount = (int) write(destinationFD, ciphertextStepBuffer, outlength);
		errorCheck(writeByteCount);
	}

	int outlength;
	EVP_EncryptFinal(ctx, ciphertextStepBuffer, &outlength);
	int ret = write(destinationFD, ciphertextStepBuffer, outlength);
	errorCheck(ret);
}

void decrypt(int sourceFD, int destinationFD, unsigned ciphertextBlockCount, unsigned blocksPerStep, const unsigned char* key, const unsigned char* iv)
{
	EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);

	EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv);

	unsigned blockLength = 128 / 8;
	unsigned stepByteCount = blockLength * blocksPerStep;

	unsigned char plaintextStepBuffer[stepByteCount];
	unsigned char ciphertextStepBuffer[stepByteCount];

	unsigned stepCount = (ciphertextBlockCount % blocksPerStep == 0 ) ? ciphertextBlockCount / blocksPerStep : (ciphertextBlockCount / blocksPerStep) + 1;

	for (unsigned step = 0; step < stepCount; step++)
	{
		int readByteCount = (int) read(sourceFD, ciphertextStepBuffer, stepByteCount);
		errorCheck(readByteCount);

		int outlength;
		EVP_DecryptUpdate(ctx, plaintextStepBuffer, &outlength, ciphertextStepBuffer, readByteCount);

		int writeByteCount = (int) write(destinationFD, plaintextStepBuffer, outlength);
		errorCheck(writeByteCount);
	}

	int outlength;
	EVP_DecryptFinal(ctx, plaintextStepBuffer, &outlength);
	int writeByteCount = write(destinationFD, plaintextStepBuffer, outlength);
	errorCheck(writeByteCount);
}