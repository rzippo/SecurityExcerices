#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>

#include "tcpSetup.h"
#include "SSLTransfer.h"

void printHelp();

int clientMain(short serverPort, char* inputFilename);
int serverMain(short listeningPort, char* outputFilename);

int main(int argc, char** argv)
{
	if (argc < 4)
	{
		printHelp();
		return 0;
	}

	if (!strcmp(argv[1], "c"))
	{
		short serverPort = (short) atoi(argv[2]);
		return clientMain(serverPort, argv[3]);
	}
	else if (!strcmp(argv[1], "s"))
	{
		short listeningPort = (short) atoi(argv[2]);
		return serverMain(listeningPort, argv[3]);
	}
	else
	{
		printHelp();
		return 0;
	}
	
	return 0;
}

void printHelp()
{
	printf("Required arguments:\n");
	printf("Letter c or s to denote the mode between client, sending the file, or server, receiving it.\n");
	printf("Port number. Clients connect to it, server listens on it. Communication is always on localhost for simplicity.\n");
	printf("File name. Client reads it, server writes to it.\n");
}

static void errorCheck(int ret)
{
	if (ret == -1)
	{
		perror(NULL);
		exit(1);
	}
}

static char* relativeToAbsolutePath(char* relative)
{
	char* buf = malloc(sizeof(char) * 500);
	getcwd(buf, 500);
	strcat(buf, "/");
	strcat(buf, relative);
	return buf;
}

int clientMain(short serverPort, char* inputFilename)
{
	int communicationSocket = connectToServer(serverPort);
	
	int inputFile = open(relativeToAbsolutePath(inputFilename), O_RDONLY);
	errorCheck(inputFile);

	
	char unsigned key[128 / 8];
	for (int i = 0; i < 128/8; i++)
	{
		key[i] = (unsigned char) ((int)'a' + i);
	}

	char unsigned iv[128 / 8];
	for (int i = 0; i < 128 / 8; i++)
	{
		iv[i] = (unsigned char)((int)'a' + i);
	}

	struct stat st;
	fstat(inputFile, &st);
	unsigned inputSize = (unsigned) st.st_size;
	uint32_t ciphertextBlockCount = (inputSize / (128 / 8)) + 1;
	ciphertextBlockCount = htonl(ciphertextBlockCount);

	write(communicationSocket, (void*)&ciphertextBlockCount, sizeof(ciphertextBlockCount));
	
	encrypt(inputFile, communicationSocket, inputSize, 4, key, iv);
	close(inputFile);

	return 0;
}

int serverMain(short listeningPort, char* outputFilename)
{
	int communicationSocket = waitClientConnection(listeningPort);

	char unsigned key[128 / 8];
	for (int i = 0; i < 128 / 8; i++)
	{
		key[i] = (unsigned char)((int)'a' + i);
	}

	char unsigned iv[128 / 8];
	for (int i = 0; i < 128 / 8; i++)
	{
		iv[i] = (unsigned char)((int)'a' + i);
	}

	uint32_t ciphertextBlockCount;
	read(communicationSocket, (void*)&ciphertextBlockCount, sizeof(ciphertextBlockCount));
	ciphertextBlockCount = ntohl(ciphertextBlockCount);

	int outputFile = open(relativeToAbsolutePath("output.txt"), O_WRONLY | O_CREAT, 0666);
	errorCheck(outputFile);

	decrypt(communicationSocket, outputFile, ciphertextBlockCount, 4, key, iv);
	close(outputFile);
	close(communicationSocket);
	
	return 0;
}