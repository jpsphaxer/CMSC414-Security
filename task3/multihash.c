# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <openssl/evp.h>
# include <openssl/rand.h>


unsigned int hash(unsigned char * buffer, unsigned char *temp,const EVP_MD * md,unsigned int hashlen, int msgsize){

     
    //size_t message_len = strlen(buffer); 
   // printf("message len is %d\n", msgsize); 


    EVP_MD_CTX *mdctx; 
    unsigned int hashlenn;

    if((mdctx = EVP_MD_CTX_new()) == NULL){
        fprintf(stderr, "evp md new failed\n");
        return 1;
    }
        //printf("after ctx new\n");  

	if(1 != EVP_DigestInit_ex(mdctx, md, NULL)){
        fprintf(stderr, "evp digest init failed\n");
        return 1; 
    }
        //printf("after digest init\n");  

	if(1 != EVP_DigestUpdate(mdctx, buffer, msgsize)){
        fprintf(stderr, "evp digest update failed\n");
        return 1; 
    }
        //printf("after digest update\n");  

	if(1 != EVP_DigestFinal_ex(mdctx, temp, &hashlen)){
        fprintf(stderr, "evp digest final failed\n");
        return 1; 
    }
        //printf("after digest final \n");  

	EVP_MD_CTX_free(mdctx);
    //printf("temp hash is %s\n",temp); 
    //printf("hash len %d\n", hashlen); 
    return hashlen; 

}



int main (int argc,char *argv[]){


    if(argc == 5){ 
        FILE * salt;
        FILE * msg; 
        const EVP_MD *md; 

        unsigned char * concatenated; 
        int saltsize; 
        int msgsize; 
        int concatsize; 

        md = EVP_get_digestbyname(argv[1]); //hash algo

        /***** algorithm null check ****/
        if (md == NULL){
            return 1; 
        }

        int hashes = atoi(argv[2]); // num hashes

        salt = fopen(argv[3], "rb"); // opening salt file
        if(salt == NULL){
            fprintf(stderr, "salt file open failed");
            return 1; 
        } 

        msg = fopen(argv[4], "rb");  // opening msg file
        if(msg == NULL){
            fprintf(stderr, "msg open failed"); 
            return 1; 
        }


        fseek(salt,0L, SEEK_END); 
        saltsize = ftell(salt); // salt file size in bytes
        rewind(salt); 
        //printf("salt size %d\n", saltsize); 


        fseek(msg,0L, SEEK_END); 
        msgsize = ftell(msg); // msg file size in bytes
        rewind(msg);
        //printf("msg size %d \n", msgsize);  

        concatsize = saltsize + msgsize;  // calculation for concatenated byte arr malloc op 
        concatenated = malloc(sizeof(unsigned char*) * concatsize + 1);

        /*****malloc check fail *****/
        if(concatenated == NULL){
            fprintf(stderr, "malloc of concat arr failure\n"); 
            return 1; 
        }

        fread(concatenated,1, saltsize, salt); //reading bytes from salt file
        fread(concatenated+saltsize, 1, msgsize, msg); // reading bytes from msg file using offset
        concatenated[concatsize +1] = '\0'; // null termination of concatenated buffer

        //printf("concatenated is %s\n", concatenated); 


        int i;
        unsigned int md_len = concatsize; // just setting this temporary but will change if the msg size changesz
        unsigned char temp[EVP_MAX_MD_SIZE]; //this buffer is guaranteed to never exceed that size 

        for(i = 0; i < hashes ; i++){
            
            md_len = hash(concatenated,temp, md, md_len, concatsize); // hash operation
            
            /**** checking if the original size is less than the temp(hash) size ****/
            /***** then we reallocate memory for the saltmsg arr ***/
            if(concatsize < md_len){
                concatsize = md_len; 
                //printf("about to realloc\n"); 
                realloc(concatenated, md_len+1); 
            }
            /***** mem copy so we can put in the hash bytes into the concatenated array for final output****/ 
            memcpy(concatenated, temp, md_len); 
        }
        concatenated[md_len+1] = '\0';

       // printf("hash is %s\n", concatenated); 

       //fwrite(concatenated,1, md_len, stdout); 

        for(i =0 ; i < md_len; i ++){
            printf("%02x",concatenated[i]);
        }
        printf("\n"); 

        free(concatenated); 

        return 0 ; 
    } else {
        return 1; 
    }

//gcc -Wall multihash.c -o multihash -lcrypto -lssl
//./multihash sha256 15 NaCl.bin msg.bin 


}