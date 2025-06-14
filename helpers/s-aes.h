#ifndef SAES_H
#define SAES_H


void generate_keys(byte* sub_keys, byte* key);  // Generates S-AES subkeys

byte nibble_sub(byte nibble); // Substitutes nibbles

void shift_row(byte* block); // Shifts rows

byte gf_16_mul(byte a, byte b); // Multiplies nibble in GF(2^4)

void enc_saes(byte* block, byte* return_block, byte* key);    // S-AES algorythm (encrypts 16-bit plaintext with 16-bit key) 

void enc_saes_debug(byte* block, byte* key); // Debug function that prints S-AES steps
#endif

