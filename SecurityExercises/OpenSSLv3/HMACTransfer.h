#pragma once

void hmacSend(int sourceFD, int destinationFD, unsigned sourceByteCount, unsigned blocksPerStep, const unsigned char* hmacKey, unsigned hmacKeyLength);
int hmacReceive(int sourceFD, int destinationFD, unsigned sourceBlockCount, unsigned blocksPerStep, const unsigned char* hmacKey, unsigned hmacKeyLength);
