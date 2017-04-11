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

static void sendBigNumber(int communicationSocket, BIGNUM* x)
{
	int xSize = BN_num_bytes(x);
	uint32_t nXSize = htonl(xSize);
	int sentBytes = write(communicationSocket, (void*) &nXSize, sizeof(uint32_t));
	errorCheck(sentBytes);

	unsigned char* xBuffer = malloc(xSize);
	BN_bn2bin(x, xBuffer);
	sentBytes = write(communicationSocket, (void*) xBuffer, xSize);
	errorCheck(sentBytes);
	free(xBuffer);
}

static void receiveBigNumber(int communicationSocket, BIGNUM* x)
{
	uint32_t nXSize;
	int receivedBytes = read(communicationSocket, (void*) &nXSize, sizeof(nXSize));
	errorCheck(receivedBytes);
	int xSize = htonl(nXSize);

	unsigned char* xBuffer = malloc(xSize);
	receivedBytes = read(communicationSocket, (void*) xBuffer, xSize);
	errorCheck(receivedBytes);

	BN_bin2bn(xBuffer, xSize, x);
	free(xBuffer);
}

static unsigned char* commonDHKeyAgreement(int communicationSocket, DH* dh)
{
	//Generate the key pair, send the public one
	if( DH_generate_key(dh) == 0)
	{
		printf("DH: Key generation failed!\n");
		exit(1);
	}
	sendBigNumber(communicationSocket, dh->pub_key);

	//Receive other's public key
	BIGNUM* p_pubKey = BN_new();
	receiveBigNumber(communicationSocket, p_pubKey);

	//Compute shared key
	unsigned char* sharedKey = malloc(512/8);
	DH_compute_key(sharedKey, p_pubKey, dh);

	//Cleanup
	BN_free(p_pubKey);
	DH_free(dh);

	return sharedKey;
}

unsigned char* serverDHKeyAgreement(int communicationSocket)
{
	//Generate and send dh parameters
	DH* dh = DH_generate_parameters(512, DH_GENERATOR_5, NULL, NULL);
	sendBigNumber(communicationSocket, dh->p);
	sendBigNumber(communicationSocket, dh->g);

	return commonDHKeyAgreement(communicationSocket, dh);
}

unsigned char* clientDHKeyAgreement(int communicationSocket)
{
	//Allocate, receive and check dh parameters
	DH* dh = DH_new();
	dh->p = BN_new();
	dh->g = BN_new();
	receiveBigNumber(communicationSocket, dh->p);
	receiveBigNumber(communicationSocket, dh->g);

	int codes;
	if(DH_check(dh, &codes) == 0 || codes != 0)
	{
		printf("DH: Parameter check failed!\n");
		exit(1);
	}

	return commonDHKeyAgreement(communicationSocket, dh);
}