#include "tcpSetup.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>

static void errorCheck(int ret)
{
	if (ret == -1)
	{
		perror(NULL);
		exit(1);
	}
}

int connectToServer(short serverPort)
{
	struct sockaddr_in serverAddress;
	memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(serverPort);
	inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);

	int communicationSocket = socket(AF_INET, SOCK_STREAM, 0);
	errorCheck(communicationSocket);

	int ret = connect(communicationSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
	errorCheck(ret);

	return communicationSocket;
}

int waitClientConnection(short listeningPort)
{
	struct sockaddr_in listeningAddress;
	memset(&listeningAddress, 0, sizeof(listeningAddress));
	listeningAddress.sin_family = AF_INET;
	listeningAddress.sin_port = htons(listeningPort);
	inet_pton(AF_INET, "127.0.0.1", &listeningAddress.sin_addr);

	int listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
	errorCheck(listeningSocket);

	int ret = bind(listeningSocket, (struct sockaddr*)&listeningAddress, sizeof(listeningAddress));
	errorCheck(ret);

	ret = listen(listeningSocket, 1);
	errorCheck(ret);

	struct sockaddr_in clientAddress;
	socklen_t clientAddressLength = sizeof(clientAddress);
	int communicationSocket = accept(listeningSocket, (struct sockaddr*)&clientAddress, &clientAddressLength);
	errorCheck(communicationSocket);

	ret = close(listeningSocket);
	errorCheck(ret);

	return communicationSocket;
}

