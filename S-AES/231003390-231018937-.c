#include <stdio.h>
#include <stdlib.h>
#include "./helpers/user_interface.h"
#include "./helpers/operation_functions.h"
#include "./helpers/s-aes.h"

// Código desenvolvido por | Luca Heringer Megiorin - 231003390
//                         | Eduardo Pereira de Sousa - 231018937
// Testado em Windows, pode apresentar comportamento indesejado em Unix (mas não foi testado, então deve funcionar)

int main(){
    int choice = 0;
    while(1){
        clrscr();
        printf("Choose an option:\n| 1. S-AES\n| 2. ECB with S-AES\n| 3. Exit\n\n");
        choice = input_int("Type the number to select your answer: ");
        if (choice == 1) {
            saes_ui_mode();
        } else if (choice == 2){
            ebc_ui_mode();
        } else if (choice == 3){
            return 0;
        }
    }
}

