#ifndef ECB_SAES_H
#define ECB_SAES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include "operation_functions.h"
#include "s-aes.h"

byte* enc_ecb_saes(string plaintext, byte* key, int* size);    // ECB mode for encrypting using S-AES

void enc_ecb_saes_debug(string plaintext, byte* key, int* size); // Debug function that prints ECB steps

#endif

