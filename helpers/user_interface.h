#ifndef USER_INTERFACE_H
#define USER_INTERFACE_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include "operation_functions.h"  // NOTE TO SELF: free everything that uses these functions
#include "s-aes.h"
#include "ecb_s-aes.h"

void saes_ui_mode(void);       // Encryption interface for s-aes cipher

void ebc_ui_mode(void);        // ECB with s-aes interface

void print_plaintext(string str, string bit_str);  // Prints plaintext that is bigger than 16 bits 
#endif