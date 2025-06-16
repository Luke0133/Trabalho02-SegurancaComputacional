#include "user_interface.h"

#define DOUBLE_BYTE 2   // Size of key/block is always 16-bit


void saes_ui_mode(void){
    clrscr();
    printf("S-AES - Encryption Mode:\nWhen prompted for a text, write it as an ASCII text, binary (start with 0b) or hexadecimal (start with 0x)\n\n");
    string key_str = NULL;
    string plaintext_str = NULL;
    byte* key = input_byte("Input a 16-bit Key: ","a",&key_str);
    byte* plaintext = input_byte("Write your 16-bit plaintext: ","a",&plaintext_str);

    clrscr();
    printf("S-AES - Encryption Mode:\n\n");

    string plaintext_64 = enc_base64(plaintext, (size_t) DOUBLE_BYTE);
    if (plaintext_64 == NULL) {
        printf("Error allocating memory for base 64 encoding\n");
        free(plaintext);
        free(key);
        free(plaintext_str);
        free(key_str);
        return;
    } else {
        printf("| Plaintext chosen:  %s  |  HEX: 0x%02X%02X  |  B64: %s\n", plaintext_str, plaintext[0], plaintext[1], plaintext_64);
        free(plaintext_64);
    }
    free(plaintext_str);

    string key_64 = enc_base64(key, (size_t) DOUBLE_BYTE);
    if (key_64 == NULL) {
        printf("Error allocating memory for base 64 encoding\n");
        free(plaintext);
        free(key);
        free(key_str);
        return;
    } else {
        printf("| Key chosen:  %s  |  HEX: 0x%02X%02X  |  B64: %s\n", key_str, key[0], key[1], key_64);
        free(key_64);
    }
    free(key_str);

    byte ciphertext[2];
    
    double start_time = get_time_ms();
    enc_saes(plaintext,ciphertext, key);
    double end_time = get_time_ms();

    enc_saes_debug(plaintext,key); // Used for printing debug messages

    string ciphertext_64 = enc_base64(ciphertext, (size_t) DOUBLE_BYTE);
    if (ciphertext_64 == NULL) {
        printf("Error allocating memory for base 64 encoding\n");
        free(key);
        free(plaintext);
        return;
    } else {
        printf("| Resulting Ciphertext: HEX: 0x%02X%02X  |  B64: %s\n", ciphertext[0], ciphertext[1], ciphertext_64);
        free(ciphertext_64);
    }

    double time_elapsed = end_time - start_time;
    printf("  - Time elapsed during encryption: %f ms\n\n", time_elapsed);

    free(key);
    free(plaintext);
    
    printf("Press ENTER key to return.\n");
    getchar();
    return;
}

void ebc_ui_mode(void){
    clrscr();
    printf("Eletronic Codebook with S-AES - Encryption Mode:\nWhen prompted for a text, write it as an ASCII text, binary (start with 0b) or hexadecimal (start with 0x)\n\n");
    string key_str = NULL;
    byte* key = input_byte("Input a 16-bit Key: ","a",&key_str);
    if (!key || !key_str) {
        printf("Failed to read key\n");
        return;
    }
    
    string plaintext_str = input_string("Write your plaintext: ");
    string plaintext = bit_seq(plaintext_str, "s");
    if (!plaintext || !plaintext_str) {
        printf("Failed to plaintext key\n");
        return;
    }

    clrscr();
    printf("Eletronic Codebook with S-AES - Encryption Mode:\n\n");
    
    print_plaintext(plaintext_str, plaintext);
    free(plaintext_str);

    string key_64 = enc_base64(key, (size_t) DOUBLE_BYTE);
    if (key_64 == NULL) {
        printf("\nError allocating memory for base 64 encoding\n");
    } else {
        printf("| Key chosen:  %s  |  HEX: 0x%02X%02X  |  B64: %s\n", key_str, key[0], key[1], key_64);
        free(key_64);
    }
    free(key_str);

    byte *ciphertext;
    int size;
    enc_ecb_saes_debug(plaintext, key, &size);

    double start_time = get_time_ms();
    ciphertext = enc_ecb_saes(plaintext, key, &size);
    double end_time = get_time_ms();

    free(key);
    free(plaintext);

    printf("| Resulting Ciphertext: HEX:");
    for (int i = 0; i < size; i++) {
        if (i % 2 == 0){
            printf(" 0x");
        }
        printf("%02X", ciphertext[i]);
    }

    string ciphertext_64 = enc_base64(ciphertext, (size_t) size);
    if (ciphertext_64 == NULL) {
        printf("\nError allocating memory for base 64 encoding\n");
        return;
    } else {
        printf(" |  B64: %s\n", ciphertext_64); 
        free(ciphertext_64);
    }
    
    free(ciphertext);

    double time_elapsed = end_time - start_time;
    printf("  - Time elapsed during encryption: %f ms\n\n", time_elapsed);

    printf("Press ENTER key to return.\n");
    getchar();
    return;
}

// Prints plaintext that is bigger than 16 bits 
void print_plaintext(string str, string bit_str){
    int len_bit = strlen(bit_str);

    printf("| Plaintext: %s", str);
    if (len_bit % 8 == 0){
        int size;
        // can be turned into a byte array
        byte* array = byte_array(bit_str, "b", &size);
        if (!array){
            printf("\nError allocating memory for byte array printing\n");
            return;
        }

        printf(" |  HEX:");
        for (int i = 0; i < size; i++) {
            if (i % 2 == 0){
                printf(" 0x");
            }
            printf("%02X", array[i]);
        }

        string plaintext_64 = enc_base64(array, (size_t) size);
        if (plaintext_64 == NULL) {
            printf("\nError allocating memory for base 64 encoding\n");
            return;
        } else {
            printf(" |  B64: %s\n", plaintext_64); 
            free(plaintext_64);
        }
        free(array);
    } else {
        int size;
        int len_converted = len_bit - len_bit%4;

        string small_str = malloc(len_converted + 1);
        strncpy(small_str,bit_str,(size_t) len_converted);
        small_str[len_converted] = '\0';

        // can be turned into a byte array
        byte* array = byte_array(small_str, "b", &size);
        free(small_str);
        if (!array){
            printf("\nError allocating memory for byte array printing\n");
            return;
        }

        printf(" |  HEX/BIN:");
        int all_full_byte = (len_converted / 4)%2; // if the array returned has all full bytes, the result will be 0
        for (int i = 0; i < size; i++) {
            if (i % 2 == 0){
                printf(" 0x");
            }
            
            printf("%X", (array[i] >> 4) & 0x0F);
            if (all_full_byte == 0 || i != size - 1){
                printf("%X", array[i] & 0x0F);
            }
        }
        if (len_bit - len_converted != 0){
            printf(" 0b%s\n", bit_str + len_converted);
        } else printf("\n");
        free(array);
    }
    return;
}