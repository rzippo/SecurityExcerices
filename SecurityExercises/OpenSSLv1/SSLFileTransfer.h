#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <openssl\evp.h>

void errorCheck(int ret)
{
	if (ret == -1)
	{
		perror(NULL);
		exit(1);
	}
}

void encrypt(int sourceFD, int destinationFD, int byteCount, const unsigned char* key)
{
	EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);

	EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, NULL);

	unsigned blockLength = 128 / 8;
	unsigned char plaintextBlock[blockLength];
	unsigned char ciphertextBlock[blockLength];

	int blockCount = byteCount / blockLength;
	for (int block = 0; block < blockLength; block++)
	{
		int ret = read(sourceFD, plaintextBlock, blockLength);
		errorCheck(ret);

		int outlength;
		EVP_EncryptUpdate(ctx, ciphertextBlock, &outlength, plaintextBlock, blockLength);
		//??

		int ret = write(destinationFD, ciphertextBlock, blockLength);
	}

}