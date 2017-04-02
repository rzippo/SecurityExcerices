// OTPBreaking.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <fcntl.h>
#include <math.h>

#include "otp.h"
#include "lcg.h"

unsigned int BOH(int values[], int length)
{
	unsigned int t = ((1 << 16)*values[1] - c*(1 << 16)*values[0] - a + (1 << 16) - 1) % (1 << 31);
	unsigned int max_k = floor( ( (1 << 16)*c - 1 - t)/(1 << 31) );
	for (unsigned int k = 0; k < max_k; k++)
	{
		if( ((t + (1 << 31)*k) % c) < (1 << 16) )
			return ( floor((t + (1 << 31)*k)/c) + (1 << 16)*values[0] );
	}
}

unsigned int bruteforce(int values[], int length)
{
	for (unsigned int k = 0; k < (1 << 31); k++)
	{
		my_srand(k);
		int valid = 1;
		for (int i = 0; i < length; i++)
		{
			if( my_rand() == values[i])
				continue;
			else
			{
				valid = 0;
				break;
			}
		}

		if(valid)
			return k;
	}
}

void bruteStrategy(FILE* fd)
{
	_cprintf("Reading firsts keystream values...\n");

	char knownPTs[3][4]; 
		knownPTs[0][0] = 'D';
		knownPTs[0][1] = 'a';
		knownPTs[0][2] = ':';
		knownPTs[0][3] = ' ';

		knownPTs[1][0] = 'G';
		knownPTs[1][1] = 'i';
		knownPTs[1][2] = 'a';
		knownPTs[1][3] = 'n';

		knownPTs[2][0] = 'l';
		knownPTs[2][1] = 'u';
		knownPTs[2][2] = 'c';
		knownPTs[2][3] = 'a';
	
			
	int knownValues[3];
	for (int i = 0; i < 3; i++)
	{
		char ct[4];
		
		for (int j = 0; j < 4; j++)
		{
			char hex[3];
			for (int k = 0; k < 3; k++)
			{
				hex[k] = fgetc(fd);
			}
			char* pEnd;
			ct[j] = (char)strtol(hex, &pEnd, 16);
		}

		knownValues[i] = *((int *) knownPTs[i]) ^ *((int *) ct);
	}
	
	_cprintf("Bruteforcing...\n");
	int key = bruteforce(knownValues, 3);
	_cprintf("Key found as %i\n", key);

	if (fseek(fd, 0, SEEK_SET))
	{
		_cprintf("Error resetting the file\n");
		return;
	}
	
	my_srand(key);
	
	_cprintf("Decrypting...\n");
	otp(fd);

}

void cleanStrategy(FILE* fd)
{
	char pt[4] = { 'D', 'a', ':', ' ' };
	char ct[4];
	for (int i = 0; i < 4; i++)
	{
		char hex[3];
		for (int j = 0; j < 3; j++)
		{
			hex[j] = fgetc(fd);
		}
		char* pEnd;
		ct[i] = (char)strtol(hex, &pEnd, 16);
	}

	int key = *((int *) pt) ^ *((int *) ct);
	my_srand(key);
	_cprintf("Decrypting...\n");
	print_bytes(pt, 4);
	otp(fd);
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		_cprintf("Errore, file non specificato");
		return;
	}
	
	_cprintf("Opening the ciphertext file...\n");
	FILE* fd = fopen(argv[1], "r");
	if (fd == NULL)
	{
		_cprintf("Errore nell'apertura del file");
		return;
	}

	//bruteStrategy(fd);
	cleanStrategy(fd);
	fclose(fd);
    return 0;
}

