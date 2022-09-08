# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <errno.h>
# include <openssl/pem.h>
# include <openssl/err.h>
# include <openssl/bio.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/rsa.h>

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16



typedef struct _cipher_params_t{
    unsigned char *key;
    unsigned char *iv; 
    unsigned int encrypt; 
    const EVP_CIPHER *cipher_type;
} cipher_params_t; 







void file_encrypt(cipher_params_t *params, FILE *infile, FILE *outfile, int in_fsize){
    
    /*allow space in output buffer for additional block*/
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);

    unsigned char in_buf[in_fsize], out_buf[in_fsize + cipher_block_size]; 

    int num_bytes_read, out_len;  
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 

    if(ctx == NULL){
        fprintf(stderr, "EVP_CIPHER_new failed : %s\n", ERR_error_string(ERR_get_error(),NULL)); 
    }
    /* Initialize cypher to aes256gcm which is an auth-encryp mode */ 
    if(1 != EVP_EncryptInit_ex(ctx,params->cipher_type,NULL,NULL,NULL)){
        fprintf(stderr, "EVP_CipherInit_ex failed : %s\n",ERR_error_string(ERR_get_error(),NULL));        
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL); 



    /*initializing key and Iv */ 
    //printf("%s , %s \n", params->key, params->iv);
    if(1 != EVP_EncryptInit_ex(ctx,NULL,NULL,params->key,params->iv)){
        fprintf(stderr, "EVP_CipherInit_ex key and iv failed : %s\n",ERR_error_string(ERR_get_error(),NULL));        
    }

   // while(1){
        num_bytes_read = fread(in_buf, sizeof(unsigned char), in_fsize, infile); 
        
        // if(1 != EVP_CipherUpdate(ctx,out_buf,&out_len,in_buf,num_bytes_read)){
        //     fprintf(stderr, "EVP_CipherUpdate failed : %s\n",ERR_error_string(ERR_get_error(),NULL));        
    
        // }

        if(1 != EVP_EncryptUpdate(ctx,out_buf, &out_len, in_buf, sizeof(in_buf))){
            fprintf(stderr, "EVP_Encryptupdate failed : %s\n",ERR_error_string(ERR_get_error(),NULL));
        }
       // fwrite(out_buf,sizeof(unsigned char), out_len, outfile); 

        // if(num_bytes_read < in_fsize){
        //     break; 
        // } 
    //}

    if(1 != EVP_EncryptFinal_ex(ctx,out_buf, &out_len)){
        fprintf(stderr, "EVP_Encryptfinal_ex failed : %s\n",ERR_error_string(ERR_get_error(),NULL));        

    }

    /*might have to get the tag*/ 
    printf("%d\n", out_len);
    fwrite(out_buf, sizeof(unsigned char), in_fsize, outfile); 

    printf("%s\n",out_buf); 

    EVP_CIPHER_CTX_cleanup(ctx); 



    

    <encrypaes key><encrypted "hello">


}





int main (int argc, char *argv[]){




    if(strcmp(argv[1],"e")==0){
        //printf("About to encrypt\n");
        FILE * f_input, *f_enc,*f_pem ;
        unsigned char key[AES_256_KEY_SIZE];
        unsigned char iv[AES_BLOCK_SIZE];
        unsigned char pubKey[2048];
        int input_fsize = 0; 
        cipher_params_t *params = (cipher_params_t*)malloc(sizeof(cipher_params_t));
       
        RAND_bytes(iv,sizeof(iv));
        RAND_bytes(key,sizeof(key));
        params->key = key;
        params->iv = iv;
        params->encrypt = 1; 
        params->cipher_type = EVP_aes_256_gcm();
        
        
        
        f_input = fopen(argv[3], "rb");//text file
        fseek(f_input,0L, SEEK_END);
        input_fsize = ftell(f_input); 
        fseek(f_input,0L,SEEK_SET); 

        //printf("%d\n", input_fsize);

        f_enc = fopen("ciphertext.bin","wb");//encrypted file 
        //fread(pubKey, sizeof(pubKey),1,fopen(argv[2],"rb"));//pem file

        
        file_encrypt(params, f_input,f_enc,input_fsize);

    }


}