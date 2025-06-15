import operation_modes as functions
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import time
import pandas as pd
import base64
import os

# Trabalho 2 de Segurança Computacional. Feito por:
# Eduardo Pereira - 231018937 
# Luca Megiorin - 231003390

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    choice = main_ui()
    #Each function call will have a timer before and after the function is done to calculate the ammount of time taken.
    start_ecb = time.perf_counter()
    result_ecb = functions.electronic_codebook(choice[0], choice[1])
    end_ecb = time.perf_counter()

    start_cbc = time.perf_counter()
    result_cbc = result = functions.cipher_block_chaining(choice[0], choice[1], choice[2])
    end_cbc = time.perf_counter()

    start_cfb = time.perf_counter()
    result_cfb = functions.cipher_feedback(choice[0], choice[1], choice[2])
    end_cfb = time.perf_counter()

    start_ofb = time.perf_counter()
    result_ofb = functions.output_feedback(choice[0], choice[1], choice[2])
    end_ofb = time.perf_counter()

    start_ctr = time.perf_counter()
    result_ctr = functions.counter(choice[0], choice[1])
    end_ctr = time.perf_counter()
    
    #Data from the operation modes is inserted into a dictionary to be displayed on a DataFrame.
    data = {
        "Plaintext": [choice[0], choice[0], choice[0], choice[0], choice[0]],
        "Key": [choice[1], choice[1], choice[1], choice[1], choice[1]],
        "Initialization Vector": ["NA", choice[2], choice[2], choice[2], "NA"],
        "Counter Range": ["NA", "NA", "NA", "NA", "0-128"],
        "Time Elapsed": [(end_ecb - start_ecb) * 1000, (end_cbc - start_cbc) * 1000, (end_cfb - start_cfb) * 1000, (end_ofb - start_ofb) * 1000, (end_ctr - start_ctr) * 1000],
        "Ciphertext (Base 64)": [base64.b64encode(result_ecb), base64.b64encode(result_cbc), base64.b64encode(result_cfb), base64.b64encode(result_ofb), base64.b64encode(result_ctr)]
    }
    df = pd.DataFrame(data, index = ["ECB", "CBC", "CFB", "OFB", "CTR"])
    print(df)

    mode = input("Press 1 to return to the Option menu, any other key to exit. ")
    if mode == "1":
        main()

def main_ui():
    while True:
        clear_screen()
        print("AES Operation Modes")
        print("Choose an Option:\n| 1. Fixed Values\n| 2. Enter your own values")
        try:
            choice = int(input("Type the number to select your answer: "))
            if choice not in [1, 2]:
                continue
            break
        except ValueError:
            pass
    match choice:
        case 1:
            return ("I am Groot.", "RandomKeyAES1234", b"1010101010101010")
        case 2:
            while True:
                key = input("Type your key. (16 bytes) ")
                if len(key) != 16:
                    continue
                plaintext = input("Type your text to be encrypted. ")
                break
            while True:
                iv_choice = input("Choose an Option:\n| 1. Random Initialization Vector\n| 2. Custom Initialization Vector ")
                if iv_choice not in ['1', '2']:
                    continue
                match iv_choice:
                    case "1":
                        initialization_vector = get_random_bytes(AES.block_size)
                        return (plaintext, key, initialization_vector)
                    case "2":
                        while True:
                            custom_iv = input("Type the initialization vector to be used. (16 bytes) ")
                            if len(custom_iv) != 16:
                                continue
                            custom_iv = custom_iv.encode('utf-8')
                            return (plaintext, key, custom_iv)  
                
if __name__ == "__main__":
    main()
