#pragma once

void encrypt(int sourceFD, int destinationFD, unsigned byteCount, unsigned blocksPerStep, const unsigned char* key, const unsigned char* iv);
void decrypt(int sourceFD, int destinationFD, unsigned byteCount, unsigned blocksPerStep, const unsigned char* key, const unsigned char* iv);
