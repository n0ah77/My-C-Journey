#include <stdio.h>


int main(){
    
    printf("What is your name?: ");
    
    char name[20];
    scanf("%s", name);    
    int age;
    printf("What's is your age?:  ");
    int result = scanf("%d", &age);

    printf("Hello, %s, Your age is %d",name, age);
    return 0;
    
}
