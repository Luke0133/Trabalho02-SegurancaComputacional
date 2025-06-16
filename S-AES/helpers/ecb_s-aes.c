#include "ecb_s-aes.h"

//Eletronic Codebook mode for S-AES encryption function:
// a string with only 0's and 1's, padds it if necessary, adds a pad info 16-bit block
// to say how many bits were padded (0-15) and applies S-AES algorythm into each block
byte* enc_ecb_saes(string plaintext, byte* key, int* size){
    int len_str = strlen(plaintext);
    int padding = (16 - len_str % 16) % 16;    // How much it needs padding
    int padded_len = len_str + padding + 16 ;  // Length of padded_str

    string padded_str = malloc(padded_len + 1);
    if (!padded_str){
        printf("Memory allocation failed.\n");
        return NULL;
    }

    strcpy(padded_str,plaintext);
    // adding padding (if any) and the first pad info byte (will always be 0, since blocks can have max of 15 bits padding, which can be represented in one byte)
    for(int i = 0; i < padding + 8; i++){
        padded_str[len_str + i] = '0';
    }

    // Add padding byte
    char pad_bits[9];
    strcpy(pad_bits, bin((byte)padding, 0));
    strncpy(padded_str + len_str + padding + 8, pad_bits, 8);
    padded_str[len_str + padding + 8 + 8] = '\0'; // NULL terminating

    byte* return_blocks = byte_array(padded_str, "b", size);
    free(padded_str);
    if (!return_blocks){
        printf("Conversion to byte array failed.\n");
        return NULL;
    }

    int n_blocks = *size/2;
    // encrypting each block of 16-bits (plus padding block)
    for (int i = 0; i < n_blocks; i++){
        byte block_plaintext[2] = {return_blocks[i * 2], return_blocks[i * 2 + 1]};
        byte block_ciphertext[2];

        // Encrypting block
        enc_saes(block_plaintext, block_ciphertext, key);

        return_blocks[i * 2] = block_ciphertext[0];
        return_blocks[1 + i * 2] = block_ciphertext[1];
    }
    return return_blocks;
}

//ECB S-AES encryption function DEBUG MODE (Prints steps):
void enc_ecb_saes_debug(string plaintext, byte* key, int* size){
    int len_str = strlen(plaintext);
    int padding = (16 - len_str % 16) % 16; // How much it needs padding
    int padded_len = len_str + padding + 16 ;  // Length of padded_str

    string padded_str = malloc(padded_len + 1);
    if (!padded_str){
        printf("Memory allocation failed.\n");
        return;
    }

    strcpy(padded_str,plaintext);
    // adding padding (if any) and the first pad info byte (will always be 0, since blocks can have max of 15 bits padding, which can be represented in one byte)
    for(int i = 0; i < padding + 8; i++){
        padded_str[len_str + i] = '0';
    }

    // Add padding byte
    char pad_bits[9];
    strcpy(pad_bits, bin((byte)padding, 0));
    strncpy(padded_str + len_str + padding + 8, pad_bits, 8);
    padded_str[len_str + padding + 8 + 8] = '\0'; // NULL terminating

    byte* return_blocks = byte_array(padded_str, "b", size);
    free(padded_str);
    if (!return_blocks){
        printf("Conversion to byte array failed.\n");
        return;
    }

    printf("| Plaintext (Padded): HEX:");
    for (int i = 0; i < *size; i++) {
        if (i % 2 == 0){
            printf(" 0x");
        }
        printf("%02X", return_blocks[i]);
    }

    string paddedtext_64 = enc_base64(return_blocks, (size_t) *size);
    if (paddedtext_64 == NULL) {
        printf("\nError allocating memory for base 64 encoding\n");
    } else {
        printf(" |  B64: %s\n", paddedtext_64); 
        free(paddedtext_64);
    }

    int n_blocks = *size/2;
    printf("| ECB for each block (Block %i is the padding info block):\n", n_blocks-1);
    for (int i = 0; i < n_blocks; i++){
        byte block_plaintext[2] = {return_blocks[i * 2], return_blocks[i * 2 + 1]};
        byte block_ciphertext[2];

        enc_saes(block_plaintext, block_ciphertext, key);
        
        printf("  - Block %i: 0x%02X%02X",i+1,block_plaintext[0], block_plaintext[1]); 

        string paddedtext_64 = enc_base64(block_plaintext, 2);
        if (paddedtext_64 == NULL) {
            printf("\nError allocating memory for base 64 encoding\n");
        } else {
            printf("  |  B64: %s  ", paddedtext_64); 
            free(paddedtext_64);
        }

        printf(" -->  Ciphertext (HEX): 0x%02X%02X",block_ciphertext[0], block_ciphertext[1]);
        string cipherblock_64 = enc_base64(block_ciphertext, 2);
        if (cipherblock_64 == NULL) {
            printf("\nError allocating memory for base 64 encoding\n");
        } else {
            printf("  |  B64: %s\n", cipherblock_64); 
            free(cipherblock_64);
        }

        return_blocks[i * 2] = block_ciphertext[0];
        return_blocks[1 + i * 2] = block_ciphertext[1];
    }
    
    free(return_blocks);
    return;
}