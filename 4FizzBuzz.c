#include<stdio.h>
void main(){
    int limit = 100;
    for (int i = 0; i < limit; i++){
        if (i % 3 == 0)
            printf("Fizz\n");
        if (i % 5 == 0)
            printf("Buzz\n");
        if (i % 3 == 0 || i % 5 ==0);
            printf("FizzBuzz\n");
    }
     
}
