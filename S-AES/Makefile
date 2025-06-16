# Compiler and Flags
CC = gcc
CFLAGS = -Wall -g

# Output files
TARGET1 = main
#TARGET2 = transfer_cipher

# Default rule to build both targets
all: $(TARGET1) $(TARGET2)

# Rule to create shift_cipher executable
#$(TARGET1): main.c ./helpers/user_interface.c ./helpers/user_interface.h ./helpers/operation_functions.c ./helpers/operation_functions.h
#	$(CC) $(CFLAGS) main.c ./helpers/user_interface.c ./helpers/operation_functions.c -o $(TARGET1) -lm
# Rule to create shift_cipher executable
$(TARGET1): main.c ./helpers/user_interface.c ./helpers/user_interface.h ./helpers/ecb_s-aes.c ./helpers/ecb_s-aes.h ./helpers/s-aes.c ./helpers/s-aes.h ./helpers/operation_functions.c ./helpers/operation_functions.h ./libb64/cdecode.c ./libb64/cdecode.h ./libb64/cencode.c ./libb64/cencode.h
	$(CC) $(CFLAGS) main.c  ./helpers/user_interface.c ./helpers/ecb_s-aes.c ./helpers/s-aes.c ./helpers/operation_functions.c ./libb64/cdecode.c ./libb64/cencode.c -o $(TARGET1) -lm

# Rule to create transfer_cipher executable
#$(TARGET2): transfer_cipher.c input_functions.c input_functions.h
#	$(CC) $(CFLAGS) transfer_cipher.c input_functions.c -o $(TARGET2)

# Clean up executables
clean:
	rm -f $(TARGET1) $(TARGET2)
