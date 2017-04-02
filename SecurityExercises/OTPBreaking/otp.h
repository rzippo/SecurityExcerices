#include <conio.h>
#include <stdio.h>
#include <stdlib.h>

#include "lcg.h"

void print_bytes(char *buf, int num)
{
	for (int i = 0; i < num; i++)
		_cprintf("%c", (unsigned char)(buf[i]));
}

void otp(FILE* fd)
{
	char pt[4], ct[4];
	int fine = 0;

	//  my_srand(s); // set the secret seed

	while (!fine)
	{
		// read 4 bytes of PT a time

		for (int i = 0; i < 4; i++)
		{
			char hex[3];
			for (int j = 0; j < 3; j++)
			{
				int c = fgetc(fd);
				hex[j] = c;
				if (c == EOF)
				{ // read until EOF
					fine = 1;
					break;
				}
			}

			char* pEnd;
			ct[i] = (char) strtol(hex, &pEnd, 16);
		}
		
		// get a PRNG value
		int r = my_rand();

		// Use the random value to encrypt the 4-bytes PT
		*((int *)pt) = r ^ *((int *)ct);
		print_bytes(pt, 4);
	}
}