#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "operation_functions.h"
#include "s-aes.h"
#include <stdint.h>
#include <stdio.h>

// NOTE: All byte arrays have the most significant bytes as the lower indexes
// for instance, a key 0x2D55 will be stored in the key array as key[0] = 0x2D and key[1] = 0x55
// The same applies to sub_keys, and blocks in general
#define ROUNDS 2

// S-Box for nibble substitution
byte SBOX[4][4] = {
    {0x9,0x4,0xA,0xB},
    {0xD,0x1,0x8,0x5},
    {0x6,0x2,0x0,0x3},
    {0xC,0xE,0xF,0x7},
};

// Key generation algorythm:
// subkey 1: [sub_keys[0],sub_keys[1]]
// subkey 2: [sub_keys[2],sub_keys[3]]
// subkey 3: [sub_keys[4],sub_keys[5]]
void generate_keys(byte* sub_keys, byte* key){
    // key 1 is the same as the original key
    sub_keys[0] = key[0];
    sub_keys[1] = key[1];

    // g(w) function is the same as [nibble_sub(lsb(w)),nibble_sub(msb(w))] XOR RCON
    // key 2: RCON = 0b10000000
    sub_keys[2] = sub_keys[0] ^ ((nibble_sub((sub_keys[1] & 0x0F)) << 4)  | nibble_sub((sub_keys[1] & 0xF0) >> 4)) ^ 0b10000000;
    sub_keys[3] = sub_keys[1] ^ sub_keys[2];

    // key 3: RCON = 0b00110000
    sub_keys[4] = sub_keys[2] ^ ((nibble_sub((sub_keys[3] & 0x0F)) << 4) | nibble_sub((sub_keys[3] & 0xF0) >> 4)) ^ 0b00110000;
    sub_keys[5] = sub_keys[3] ^ sub_keys[4];
    return;
}  

// Nibble Substitution algorithm: recieves a nibble (assumes it's the 4 rightmost - lsb - bits of a byte)
// and applies the substitution box
byte nibble_sub(byte nibble){
    return SBOX[(nibble & 0xC) >> 2][(nibble & 0x3)];
}

// Shift Row algorithm: recieves two bytes (a block) and swaps the bottom row:
//    MSB(block[0])  MSB(block[1])  -->  MSB(block[0])  MSB(block[1])
//    LSB(block[0])  LSB(block[1])  -->  LSB(block[1])  LSB(block[0])
void shift_row(byte* block){
    byte shift_result[2];

    // Swapping bottom row
    shift_result[0] = (block[0] & 0xF0) | (block[1] & 0x0F);
    shift_result[1] = (block[1] & 0xF0) | (block[0] & 0x0F);

    block[0] = shift_result[0];
    block[1] = shift_result[1];
    return;
}

// Multiplication in the GF(2^4) with modulo x^4+x+1 -> 0b10011
byte gf_16_mul(byte a, byte b) {
    byte result = 0;
    //printf("mul: %02X x  %02X = ", a , b);  // DEBUG MUL

    // loops 4 times, since n = 4
    for (int i = 0; i < 4; i++){
        if (b & 1) // if current bit from b is 1
            result ^= a; // add current shifted value of a

        byte msb_nibble = a & 0x8; // Stores nibble's msb
        a <<= 1;
        if (msb_nibble)    // If msb is on fith bit, reduce it
            a ^= 0x13;     // reduce modulo x^4 + x + 1
        b >>= 1; // Move to next bit of b
    }
    //printf("%02X\n", result);  // DEBUG MUL
    return result & 0xF;
}

//S-AES encryption function:
// recieves 16-bit block and a 16-bit key and "returns" an encrypted block
// In this function, the pointer to the encrypted block is passed 
// as an argument so that the function doesn't need to allocate memory
void enc_saes(byte* block, byte* return_block, byte* key){
    byte sub_keys[6];
    generate_keys(sub_keys, key);
    
    // Add round key (Before first round)
    return_block[0] = block[0] ^ sub_keys[0];
    return_block[1] = block[1] ^ sub_keys[1];

    // S-AES rounds
    for (int i = 0; i < ROUNDS; i++){
        // Substitute Nibbles
        // For each round, will substitute nibbles of the MSB and the LSB of each byte of the return block
        return_block[0] = (nibble_sub((return_block[0] & 0xF0) >> 4) << 4) | nibble_sub((return_block[0] & 0x0F));
        return_block[1] = (nibble_sub((return_block[1] & 0xF0) >> 4) << 4) | nibble_sub((return_block[1] & 0x0F));  

        // Shift Rows
        shift_row(return_block);

        // Mix Columns (not applied on last round)
        // with | a  c | and | 1  4 |  so then, for each column | n | we do | 1  4 |  *  | n |  
        //      | b  d |     | 4  1 |                           | m |       | 4  1 |     | m |  
        //  a = MSB(return_block[0])  c = MSB(return_block[1])  ==>  output: | a' b'|
        //  b = LSB(return_block[0])  d = LSB(return_block[1])               | c' d'|
        if (i != ROUNDS - 1){
            byte a = ((return_block[0] & 0xF0) >> 4);
            byte b = (return_block[0] & 0x0F);
            byte c = ((return_block[1] & 0xF0) >> 4);
            byte d = (return_block[1] & 0x0F);

            // return_block[0]' => MSB: a' = a XOR (4 X b); LSB: b' = (4 X a) XOR b
            return_block[0] = ((a ^ gf_16_mul(4, b)) << 4) | (gf_16_mul(4, a) ^ b); 
            // return_block[1]' => MSB: c' = c XOR (4 X d); LSB: d' = (4 X c) XOR d
            return_block[1] = ((c ^ gf_16_mul(4, d)) << 4) | (gf_16_mul(4, c) ^ d);
        }

        // Add round key
        // subkey 2: [sub_keys[2],sub_keys[3]]
        // subkey 3: [sub_keys[4],sub_keys[5]]
        return_block[0] = return_block[0] ^ sub_keys[2 + 2 * i];
        return_block[1] = return_block[1] ^ sub_keys[3 + 2 * i];
    }
    return;
}


//S-AES encryption function DEBUG MODE (Prints steps):
void enc_saes_debug(byte* block, byte* key){
    byte return_block[2];
    byte sub_keys[6];
    generate_keys(sub_keys, key);

    byte subkey[2];
    // Printing Subkeys
    printf("| Subkeys Generated:\n");
    string subkey_64;
    for (int i = 0; i < 3; i++){
        subkey[0] = sub_keys[i * 2];
        subkey[1] = sub_keys[1 + i * 2];
        subkey_64 = enc_base64(subkey, 2);
        if (subkey_64 == NULL) {
            printf("Error allocating memory for base 64 encoding\n");
            return;
        } else {
            printf("  - Subkey %i:  0x%02X%02X  |  B64: %s\n", i+1, subkey[0], subkey[1], subkey_64);
            free(subkey_64);
        }
    }
    return_block[0] = block[0] ^ sub_keys[0];
    return_block[1] = block[1] ^ sub_keys[1];
    // Printing AddRoundKey
    string return_block_64 = enc_base64(return_block, 2);
    if (return_block_64 == NULL) {
        printf("Error allocating memory for base 64 encoding\n");
        return;
    } else {
        printf("| Iteration 0:\n  - AddRoundKey: 0x%02X%02X  |  B64: %s\n", return_block[0], return_block[1], return_block_64);
        free(return_block_64);
    }
    
    for (int i = 0; i < ROUNDS; i++){
        printf("| Iteration %i:\n", i+1);
        return_block[0] = (nibble_sub((return_block[0] & 0xF0) >> 4) << 4) | nibble_sub((return_block[0] & 0x0F));
        return_block[1] = (nibble_sub((return_block[1] & 0xF0) >> 4) << 4) | nibble_sub((return_block[1] & 0x0F));   
        // Printing Substitute Nibbles
        return_block_64 = enc_base64(return_block, 2);
        if (return_block_64 == NULL) {
            printf("Error allocating memory for base 64 encoding\n");
            return;
        } else {
        printf("  - SubNibbles: 0x%02X%02X   |  B64: %s\n", return_block[0], return_block[1], return_block_64);
            free(return_block_64);
        }
        // Printing Shift Rows
        shift_row(return_block);
        return_block_64 = enc_base64(return_block, 2);
        if (return_block_64 == NULL) {
            printf("Error allocating memory for base 64 encoding\n");
            return;
        } else {
        printf("  - ShiftRows: 0x%02X%02X    |  B64: %s\n", return_block[0], return_block[1], return_block_64);
            free(return_block_64);
        }
        if (i != ROUNDS - 1){
            byte a = ((return_block[0] & 0xF0) >> 4);
            byte b = (return_block[0] & 0x0F);
            byte c = ((return_block[1] & 0xF0) >> 4);
            byte d = (return_block[1] & 0x0F);
            return_block[0] = ((a ^ gf_16_mul(4, b)) << 4) | (gf_16_mul(4, a) ^ b); 
            return_block[1] = ((c ^ gf_16_mul(4, d)) << 4) | (gf_16_mul(4, c) ^ d);
            // Printing MixColumns
            return_block_64 = enc_base64(return_block, 2);
            if (return_block_64 == NULL) {
                printf("Error allocating memory for base 64 encoding\n");
                return;
            } else {
            printf("  - MixColumns: 0x%02X%02X   |  B64: %s\n", return_block[0], return_block[1], return_block_64);
                free(return_block_64);
            }
        }
        return_block[0] = return_block[0] ^ sub_keys[2 + 2 * i];
        return_block[1] = return_block[1] ^ sub_keys[3 + 2 * i];
        // Printing AddRoundKey
        return_block_64 = enc_base64(return_block, 2);
        if (return_block_64 == NULL) {
            printf("Error allocating memory for base 64 encoding\n");
            return;
        } else {
        printf("  - AddRoundKey: 0x%02X%02X  |  B64: %s\n", return_block[0], return_block[1], return_block_64);
            free(return_block_64);
        }
    }
    return;
}
