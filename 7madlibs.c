#include <stdio.h>

/* 
This is a simple madlibs game.
*/

int main(){
    printf("Write an adjective: ");
    char word1[20];
    scanf("%s", word1);

    printf("Write a noun: ");
    char word2[20];
    scanf("%s", word2);
    
    printf("Write an adjective: ");
    char word3[20];
    scanf("%s", word3);
    
    printf("Write a plural noun: ");
    char word4[20];
    scanf("%s", word4);
    
    printf("Write a verb: ");
    char word5[20];
    scanf("%s", word5);
    
    printf("Write a noun: ");
    char word6[20];
    scanf("%s", word6);
    
    printf("Plural noun (items in a basket) ");
    char word7[20];
    scanf("%s", word7);

    printf("Write a noun (unexpected misfortune):");
    char word8[20];
    scanf("%s", word8);

    printf("Write a noun (place): ");
    char word9[20];
    scanf("%s", word9); 
    
    printf("write a verb or a resulting state adjective: ");
    char word10[20];
    scanf("%s", word10); 


    printf("On one %s day, a %s decided to throw a party for all of the %s %s. \nThey %s into the big %s with a basket full of %s. \nThey took a %s at %s and ended up %s.\nThe end.",word1,word2,word3,word4,word5,word6,word7,word8,word9,word10);
};

