#include "HMACTransfer.h"

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

void hmacSend(int sourceFD, int destinationFD, unsigned sourceByteCount, unsigned blocksPerStep, const unsigned char* hmacKey, unsigned hmacKeyLength)
{
	HMAC_CTX* hmacCtx = malloc(sizeof(HMAC_CTX));
	HMAC_CTX_init(hmacCtx);

	HMAC_Init(hmacCtx, hmacKey, hmacKeyLength, EVP_md5());

	unsigned blockLength = 128 / 8;
	unsigned stepByteCount = blockLength * blocksPerStep;

	unsigned char transferBuffer[stepByteCount];

	unsigned stepCount = (sourceByteCount % stepByteCount == 0) ? sourceByteCount / stepByteCount : (sourceByteCount / stepByteCount) + 1;

	for (unsigned currentStep = 0; currentStep < stepCount; currentStep++)
	{
		int readByteCount = (int) read(sourceFD, transferBuffer, stepByteCount);
		errorCheck(readByteCount);

		HMAC_Update(hmacCtx, transferBuffer, readByteCount);

		int writeByteCount = (int) write(destinationFD, transferBuffer, readByteCount);
		errorCheck(writeByteCount);
	}

	unsigned char digestBuffer[EVP_MD_size(EVP_md5())];
	unsigned outlength;
	HMAC_Final(hmacCtx, digestBuffer, &outlength);
	int ret = write(destinationFD, digestBuffer, outlength);
	errorCheck(ret);

	//Cleanup
	HMAC_CTX_cleanup(hmacCtx);
	free(hmacCtx);
}

int hmacReceive(int sourceFD, int destinationFD, unsigned sourceBlockCount, unsigned blocksPerStep, const unsigned char* hmacKey, unsigned hmacKeyLength)
{
	HMAC_CTX* hmacCtx = malloc(sizeof(HMAC_CTX));
	HMAC_CTX_init(hmacCtx);

	HMAC_Init(hmacCtx, hmacKey, hmacKeyLength, EVP_md5());

	unsigned blockLength = 128 / 8;
	unsigned stepByteCount = blockLength * blocksPerStep;

	unsigned char transferBuffer[stepByteCount];

	unsigned stepCount = (sourceBlockCount % blocksPerStep == 0) ? sourceBlockCount / blocksPerStep : (sourceBlockCount / blocksPerStep) + 1;

	for (unsigned currentStep = 0; currentStep < stepCount; currentStep++)
	{
		int readByteCount = (int) read(sourceFD, transferBuffer, stepByteCount);
		errorCheck(readByteCount);

		HMAC_Update(hmacCtx, transferBuffer, readByteCount);

		int writeByteCount = (int) write(destinationFD, transferBuffer, readByteCount);
		errorCheck(writeByteCount);
	}

	unsigned char computedDigestBuffer[EVP_MD_size(EVP_md5())];
	unsigned outlength;
	HMAC_Final(hmacCtx, computedDigestBuffer, &outlength);
	
	unsigned char receivedDigestBuffer[EVP_MD_size(EVP_md5())];
	int readByteCount = read(destinationFD, receivedDigestBuffer, EVP_MD_size(EVP_md5()));
	errorCheck(readByteCount);

	//Cleanup
	HMAC_CTX_cleanup(hmacCtx);
	free(hmacCtx);

	return !CRYPTO_memcmp(computedDigestBuffer, receivedDigestBuffer, EVP_MD_size(EVP_md5()));
}