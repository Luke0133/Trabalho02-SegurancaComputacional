#ifndef OPERATION_FUNCTIONS_H
#define OPERATION_FUNCTIONS_H

#include <stdint.h>

typedef char* string;
typedef uint8_t byte;
#define MAX_LENGTH 2048
#define APLHA_LEN 26  // Alphabet length

const string bin(byte x, int padding);

const string hex_to_bin(char hex);

byte* byte_array(string input, string type, int* array_size);

byte* input_byte(string query_text, string type, string *input);  // Prompts for input and returns byte

string bit_seq(string input, string type);

int input_int(string query_text);          // Gets input as int

string input_string(string query_text);    // Gets input as char* (string)

void strip_spaces(string s);           // Removes spaces from string

char* enc_base64(const uint8_t *input, size_t length); //, size_t *out_len);

void clrscr(void);                        // Clear screen

double get_time_ms();

#endif