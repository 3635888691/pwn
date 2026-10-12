#include <stdio.h>

int main(void)
{
    char name[64];
    printf("Enter your name: \n");
    read(0 , name , 1024);
    printf("bye!\n");
    return 0;
}

void win(void)
{
    printf("You win!\n");
    system("/bin/sh");
    exit(0);
}