#include "DHKeyAgreement.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <arpa/inet.h>
#include <openssl/dh.h>

static void errorCheck(int ret)
{
	if (ret == -1)
	{
		perror(NULL);
		exit(1);
	}
}

static void sendPublicKey(int communicationSocket, DH* dh)
{
	if( DH_generate_key(dh) == 0)
	{
		printf("DH: Key generation failed!\n");
		exit(1);
	}

	int publicKeySize = BN_num_bytes(dh->pub_key);
	uint32_t nPublicKeySize = htonl(publicKeySize);
	int sentBytes = write(communicationSocket, (void*) &nPublicKeySize, sizeof(nPublicKeySize));
	errorCheck(sentBytes);

	unsigned char* publicKeyBuffer = malloc(publicKeySize);
	BN_bn2bin(dh->pub_key, publicKeyBuffer);
	sentBytes = write(communicationSocket, (void*) publicKeyBuffer, publicKeySize);
	errorCheck(sentBytes);

	free(publicKeyBuffer);
}

static void receivePublicKey(int communicationSocket, BIGNUM* p_pubKey)
{
	uint32_t nPublicKeySize;
	int receivedBytes = read(communicationSocket, (void*) &nPublicKeySize, sizeof(nPublicKeySize));
	errorCheck(receivedBytes);
	int publicKeySize = htonl(nPublicKeySize);

	unsigned char* publicKeyBuffer = malloc(publicKeySize);
	receivedBytes = read(communicationSocket, (void*) publicKeyBuffer, publicKeySize);
	errorCheck(receivedBytes);

	BN_bin2bn(publicKeyBuffer, publicKeySize, p_pubKey);
	free(publicKeyBuffer);
}

unsigned char* serverDHKeyAgreement(int communicationSocket)
{
	DH* dh = DH_generate_parameters(512, DH_GENERATOR_5, NULL, NULL);
	int sentBytes = write(communicationSocket, (void*) dh, sizeof(DH));
	errorCheck(sentBytes);

	sendPublicKey(communicationSocket, dh);
	BIGNUM* p_pubKey = BN_new();
	receivePublicKey(communicationSocket, p_pubKey);

	unsigned char* sharedKey = malloc(512 * sizeof(unsigned char));
	DH_compute_key(sharedKey, p_pubKey, dh);

	return sharedKey;
}

unsigned char* clientDHKeyAgreement(int communicationSocket)
{
	DH dh;
	int receivedBytes = read(communicationSocket, (void*) &dh, sizeof(DH));
	errorCheck(receivedBytes);

	int codes;
	if(DH_check(&dh, &codes) == 0 || codes != 0)
	{
		printf("DH: Parameter check failed!\n");
		exit(1);
	}

	sendPublicKey(communicationSocket, &dh);
	BIGNUM* p_pubKey = BN_new();
	receivePublicKey(communicationSocket, p_pubKey);

	unsigned char* sharedKey = malloc(512 * sizeof(unsigned char));
	DH_compute_key(sharedKey, p_pubKey, &dh);

	return sharedKey;
}