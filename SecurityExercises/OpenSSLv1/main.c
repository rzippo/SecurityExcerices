#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tcpSetup.h"

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

	if (strcmp(argv[1], "c"))
	{
		short serverPort = atoi(argv[2]);
		return clientMain(serverPort, argv[3]);
	}
	else if (strcmp(argv[1], "s"))
	{
		short listeningPort = atoi(argv[2]);
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

int clientMain(short serverPort, char* inputFilename)
{
	int communicationSocket = connectToServer(serverPort);
}

int serverMain(short listeningPort, char* outputFilename)
{
	int communicationSocket = waitClientConnection(listeningPort);
}