#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "Typedefs.h"

char get_rand_char() {
    char characters[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    int random_index = rand() % (sizeof(characters) - 1);
    return characters[random_index];
}

void information_gatherer(Victim *victim){
    char random_string[11];

    srand(time(NULL));

    for (int i = 0; i < 11; i++) {
        random_string[i] = get_rand_char();
    }   

    memcpy(victim->ID, random_string, 11);
}