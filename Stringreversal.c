#include <stdio.h>
#include <string.h>

int main(void){
    char str[6] = "Hello";
    
    int end = strlen(str) - 1;

    for (int start = 0; start < end; start++, end--){
       
    char temp = str[start];
    str[start] = str[end];
    str[end] = temp;
    }

    printf("%s", str);
}
