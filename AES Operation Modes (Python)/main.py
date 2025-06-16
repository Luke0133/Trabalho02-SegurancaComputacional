import operation_modes as functions
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from tabulate import tabulate
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
    while (True):
        choice = main_ui()
        if not choice: return
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
        result_ctr = functions.counter(choice[0], choice[1], choice[2])
        end_ctr = time.perf_counter()
        
        #Data from the operation modes is inserted into a dictionary to be displayed on a DataFrame.
        data = {
            "Plaintext": [choice[0], choice[0], choice[0], choice[0], choice[0]],
            "Key": [choice[1], choice[1], choice[1], choice[1], choice[1]],
            "Initialization Vector": ["NA", choice[2], choice[2], choice[2], choice[2]],
            "Time Elapsed": [(end_ecb - start_ecb) * 1000, (end_cbc - start_cbc) * 1000, (end_cfb - start_cfb) * 1000, (end_ofb - start_ofb) * 1000, (end_ctr - start_ctr) * 1000],
            "Ciphertext (Base 64)": [base64.b64encode(result_ecb), base64.b64encode(result_cbc), base64.b64encode(result_cfb), base64.b64encode(result_ofb), base64.b64encode(result_ctr)]
        }
        df = pd.DataFrame(data, index = ["ECB", "CBC", "CFB", "OFB", "CTR"])
        print(tabulate(df, headers='keys', tablefmt='github', stralign='center'))

        input("Press any key to continue")

def main_ui():
    while True:
        clear_screen()
        print("AES Operation Modes")
        print("Choose an Option:\n| 1. Fixed Values\n| 2. Enter your own values\n| 3. Exit")
        try:
            choice = int(input("Type the number to select your answer: "))
            if choice not in [1, 2, 3]:
                continue
            break
        except ValueError:
            pass
    match choice:
        case 1:
            return ("I am Groot.", "RandomKeyAES1234", b"1010101010101010")
        case 2:
            while True:
                clear_screen()
                print("AES Operation Modes - Custom Values")
                key = input("Type your key (16 bytes): ")
                if len(key) != 16:
                    continue
                clear_screen()
                print("AES Operation Modes - Custom Values")
                print(f"Type your key (16 bytes): {key}")
                plaintext = input("Type your text to be encrypted: ")
                break
            while True:
                clear_screen()
                print("AES Operation Modes - Custom Values")
                print(f"Type your key (16 bytes): {key}")
                print(f"Type your text to be encrypted: {plaintext}\n")
                iv_choice = input("Choose an Option:\n| 1. Random Initialization Vector\n| 2. Custom Initialization Vector\nType your answer: ")
                if iv_choice not in ['1', '2']:
                    continue
                match iv_choice:
                    case "1":
                        initialization_vector = get_random_bytes(AES.block_size)
                        return (plaintext, key, initialization_vector)
                    case "2":
                        while True:
                            clear_screen()
                            print("AES Operation Modes - Custom Values")
                            print(f"Type your key (16 bytes): {key}")
                            print(f"Type your text to be encrypted: {plaintext}")
                            custom_iv = input("Type the initialization vector to be used (16 bytes): ")
                            if len(custom_iv) != 16:
                                continue
                            custom_iv = custom_iv.encode('utf-8')
                            return (plaintext, key, custom_iv)  
        case _:
            return None
                
if __name__ == "__main__":
    main()
