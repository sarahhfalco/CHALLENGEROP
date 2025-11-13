#include <stdio.h>

int flag;

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Please, enter your name!\n");
    }

    printf(argv[1]);

    if (flag) {
        printf("\n\nYou win!\n");
    } else {
        printf("\n\nI am sorry! Try again!");
    }

    return 0;
}
