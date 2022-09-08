# include <stdio.h>
# include <stdlib.h>
# include <openssl/evp.h>
# include <openssl/rand.h>



int main (int argc,char *argv[]){


    unsigned char * salt;
    unsigned char * msg; 

    int random=150; 
    int random2=8;

    salt = malloc(random); 
    msg = malloc(random); 

    RAND_bytes(salt, random); 
    RAND_bytes(msg, random2);  
    printf("%s\n", salt);
    printf("%s\n", msg);

    FILE * sal;
    FILE * message;

    sal = fopen("NaCl.bin", "wb");
    message =fopen("msg.bin", "wb"); 

    fwrite(salt, 1,  random, sal);
    fwrite(msg, 1,  random, message);


    return 0; 


}