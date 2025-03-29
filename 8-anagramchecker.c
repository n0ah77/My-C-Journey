#include<stdio.h>
#include<string.h>

// This code checks if the 2 words use the same exact letters and letter count (example: iceman & cinema)
int main() {
int counter1[] = {0,0,0,0};
int counter2[] = {0,0,0,0};
int flag = 0;

// The two words to check for an anagram
char s1[] = "aaad";
char s2[] = "aaaa";

// Adding a value to each letter
for (int i = 0; i < strlen(s1); i++){
  if (s1[i] == 'a'){
    counter1[0] += 1;};
  if (s1[i] == 'b'){
    counter1[1] += 1;};
  if (s1[i] == 'c'){
    counter1[2] += 1;};
  if (s1[i] == 'd'){
    counter1[3] += 1;};
}
for (int i = 0; i < strlen(s2); i++){
  if (s2[i] == 'a'){
    counter2[0] += 1;}
  if (s2[i] == 'b'){
    counter2[1] += 1;}
  if (s2[i] == 'c'){
    counter2[2] += 1;}
  if (s2[i] == 'd'){
    counter2[3] += 1;}
}

// looping to see if the counters differ, if it differs, it sets "flag" to 1 and breaks the loop.
  
  for (int i = 0; i < 4; i++){ 
      if (counter1[i] != counter2[i]){
        flag = 1;
        break;}
 }
// checks and prints if its an anagram based off of the int variable "flag".
if(flag == 0){
  printf("Anagram");
} else{
  printf("Not Anagram!");
}
}
