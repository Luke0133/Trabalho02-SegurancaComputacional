#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <math.h>
#include "operation_functions.h"
#include "../libb64/cencode.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/time.h>
#endif

#define BYTE_SIZE 8

const string bin(byte x, int padding)                     
{                                                 
    static char buf[9];     
    for (int i = 0; i < BYTE_SIZE; i++) {
        if (padding == 0 || i < BYTE_SIZE - padding){
            buf[i] = (x & (1 << (7 - i))) ? '1' : '0';
        }
        else buf[i] = '\0';
    }

    buf[BYTE_SIZE] = '\0';
    return buf;                                  
}

const string hex_to_bin(char hex) {
    switch(hex) {
        case '0': return "0000";
        case '1': return "0001";
        case '2': return "0010";
        case '3': return "0011";
        case '4': return "0100";
        case '5': return "0101";
        case '6': return "0110";
        case '7': return "0111";
        case '8': return "1000";
        case '9': return "1001";
        case 'A': case 'a': return "1010";
        case 'B': case 'b': return "1011";
        case 'C': case 'c': return "1100";
        case 'D': case 'd': return "1101";
        case 'E': case 'e': return "1110";
        case 'F': case 'f': return "1111";
        default:  return NULL;  // Invalid hex character
    }
}

// Prompts for a string and turns it into an array of 2 bytes
// type: h - hex, b - bin, a - any, s - string (default)
byte* input_byte(string query_text, string type, string *input){
    byte* output;
    int size;

    while (1){
        int valid = 1;
        *input = input_string(query_text);  
        strip_spaces(*input);

        char *actual_input = *input;
    
        if (strncmp(*input, "0b", 2) == 0 || strncmp(*input, "0x", 2) == 0) {
            actual_input += 2;
        }
        
        if ((!strcmp(type, "b") || (!strcmp(type, "a") && (strncmp(*input, "0b", 2) == 0))) && (strlen(actual_input) % 8 == 0) && (strlen(actual_input) / 8 == 2)) {
            for (int i = 0; i < strlen(actual_input); i++) {
                if (actual_input[i] != '1' && actual_input[i] != '0') {
                    valid = 0;
                    break;
                }
            }
            if (valid){
                output = byte_array(actual_input, "b", &size);
                return output;
            }
        } else if ((!strcmp(type, "h") || (!strcmp(type, "a") && (strncmp(*input, "0x", 2) == 0))) &&  (strlen(actual_input) % 2 == 0) && (strlen(actual_input) / 2 == 2)) {
            for (int i = 0; i < strlen(actual_input); i++) {
                if (!isdigit(actual_input[i]) && tolower(actual_input[i]) != 'a' && tolower(actual_input[i]) != 'b' && tolower(actual_input[i]) != 'c' 
                    && tolower(actual_input[i]) != 'd' && tolower(actual_input[i]) != 'e' && tolower(actual_input[i]) != 'f') {
                    valid = 0;
                    break;
                }
            }
            if (valid){
                output = byte_array(actual_input, "h", &size); // padding will always be 0 in this scenario
                return output;
            }
        } else if ((!strcmp(type, "s") || (!strcmp(type, "a") && (strncmp(*input, "0b", 2) != 0) && (strncmp(*input, "0x", 2) != 0)))) {
            if (strlen(*input) == 2){
                output = byte_array(actual_input, "s", &size);
                return output;
            }
        }

    }
} 

byte* byte_array(string input, string type, int* array_size){
    char *actual_input = input;
    
    // Check for "0b" or "0x" prefix and skip them
    if (strncmp(input, "0b", 2) == 0 || strncmp(input, "0x", 2) == 0) {
        actual_input += 2;
    }

    if (!strcmp(type, "b") || strncmp(input, "0b", 2) == 0) {
        int input_len = strlen(actual_input);
        int padding_needed = 0;
        if (input_len % BYTE_SIZE != 0) {
            padding_needed = BYTE_SIZE - input_len%BYTE_SIZE;
            *array_size = ceil(input_len / (float) BYTE_SIZE);
        } else *array_size = input_len / BYTE_SIZE;
        
        byte *array = malloc(*array_size);
        if (!array) {
            return NULL;
        }

        for (int i = 0; i < *array_size; i++) {
            byte val = 0;
            for (int j = 0; j < BYTE_SIZE; j++) {
                char bit;
                if (i == *array_size - 1 && j >= BYTE_SIZE - padding_needed){
                    bit = '0';
                } else {
                    bit = actual_input[i * BYTE_SIZE + j];
                }
                
                if (bit == '1') {
                    val |= (1 << (7 - j));
                } else if (bit != '0') {
                    printf("Invalid binary character: %c\n", bit);
                    free(array);
                    return NULL;
                }
            }
            array[i] = val;
        }      
        return array;

    } else if (!strcmp(type, "h") || strncmp(input, "0x", 2) == 0) {
        int input_len = strlen(actual_input);
        *array_size = input_len / 2;

        byte *array = malloc(*array_size);
        if (!array) return NULL;

        for (int i = 0; i < *array_size; i++) {
            char hex_pair[3] = {actual_input[i * 2], actual_input[i * 2 + 1], '\0'};
            array[i] = (byte)strtol(hex_pair, NULL, 16);       
        }

        return array;

    } else { //Turning string into byte array (default)
        // no padding needed, ascii is always 8 bits
        *array_size = strlen(input);
        byte *array = malloc(*array_size);
        if (!array) return NULL;

        for (int i = 0; i < *array_size; i++) {
            array[i] = (byte)input[i];
        }

        return array;
    }

}

string bit_seq(string input, string type){
    int length;
    strip_spaces(input);
    char *actual_input = input;
    
    // Check for "0b" or "0x" prefix and skip them
    if (strncmp(input, "0b", 2) == 0 || strncmp(input, "0x", 2) == 0) {
        actual_input += 2;
    }
    
    int input_len = strlen(actual_input); 
    
    if (!strcmp(type, "b") || strncmp(input, "0b", 2) == 0) {
        length = input_len;
        
        string bits = malloc(length + 1);
        if (!bits) return NULL;

        strcpy(bits, actual_input);
        bits[length] = '\0';
        
        return bits;

    } else if (!strcmp(type, "h") || strncmp(input, "0x", 2) == 0) {
        length = 4 * input_len;

        string bits = malloc(length + 1);
        if (!bits) return NULL;

        bits[0] = '\0';

        for (int i = 0; i < input_len; i++) {
            const string bin_value = hex_to_bin(actual_input[i]);
            if (bin_value){
                strcat(bits,bin_value);  
            } else {
                free(bits);
                printf("Invalid hex character: %c\n", actual_input[i]);
                return NULL;
            }
        }
        bits[length] = '\0';
        return bits;

    } else { //Turning string into byte array (default)
        // no padding needed, ascii is always 8 bits
        length = 8 * input_len;
        string bits = malloc(length + 1);
        if (!bits) return NULL;

        bits[0] = '\0';

        for (int i = 0; i < input_len; i++) {
            strcat(bits,bin((byte)input[i], 0));
        }
        bits[length] = '\0';
        return bits;
    }

}


int input_int(string query_text){
    while (1) {
        string buffer = input_string(query_text);
        int i = atoi(buffer);
        if (i != 0) {
            free(buffer);
            return i;
        } else {
            int len = strlen(buffer); 
            int isZero = 1; // True
            
            if (buffer[0] != '-' && buffer[0] != '0'){
                isZero = 0;
            }

            int n = 1;
            while (n < len && isZero){
                if (!isdigit(buffer[n])){
                    isZero = 0;  
                }
                n++;
            }

            if (isZero){
                free(buffer);
                return i;
            }
        }
    }
}


string input_string(string query_text){
    while (1) {
        printf("%s", query_text); // Printing query 

        size_t size = 1;                       // Initial allocation size
        string s = malloc(size * sizeof(char)); // Allocating memory for input
        
        // Checking malloc success
        if (s == NULL) {
            printf("Error allocating memory. Program terminated.\n");
            exit(1);
        }

        // Input loop to handle dynamic resizing
        size_t length = 0;
        int character;
        while ((character = getchar()) != '\n' && character != EOF) {
            s[length++] = character;
            
            // Resize buffer if necessary
            if (length >= size) {
                size += 1;
                s = realloc(s, size * sizeof(char));      // Reallocate memory
                if (s == NULL) {
                    free(s);
                    printf("Error reallocating memory. Program terminated.\n");
                    exit(1);
                }
            }
        }
        
        s[length] = '\0';    // Null-terminate the string
        
        // If there's input, return (otherwise, prompt again)
        if (length != 0) {
            return s;
        }
    }
}

void strip_spaces(string s){
    int i = 0, j = 0;
    while (s[i] != '\0') {
        if (s[i] != ' ') {
            s[j] = s[i];
            j++;
        }
        i++;
    }
    s[j] = '\0';
}

char* enc_base64(const uint8_t *input, size_t length){ //, size_t *out_len) {
    base64_encodestate state;

    // Base64-encoded size: 4/3 of input, rounded up, plus padding and null terminator
    size_t encoded_buf_size = ((length + 2) / 3) * 4 + 1;
    string encoded = malloc(encoded_buf_size);
    if (!encoded) return NULL;

    base64_init_encodestate(&state);
    int cnt = base64_encode_block((const char *)input, length, encoded, &state);
    cnt += base64_encode_blockend(encoded + cnt, &state);
    encoded[cnt] = '\0';

    // if (out_len) *out_len = cnt;
    return encoded;
}

void clrscr() {
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
}

double get_time_ms() {
    #ifdef _WIN32
        LARGE_INTEGER freq, counter;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&counter);
        return (double)counter.QuadPart * 1000.0 / freq.QuadPart;
    #else
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (double)(tv.tv_sec) * 1000.0 + (double)(tv.tv_usec) / 1000.0;
    #endif
}