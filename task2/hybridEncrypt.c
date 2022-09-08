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




int file_encrypt(cipher_params_t *params, FILE *infile, FILE *outfile, int in_fsize, char * pemfile){
    
    /*allow space in output buffer for additional block*/
    //int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
    //printf("%d\n", cipher_block_size); 

    unsigned char in_buf[in_fsize], out_buf[in_fsize]; 
    unsigned char tag[16]; 
    int num_bytes_read, out_len;  

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 

       
    //printf("the key is %s\n", params->key); 

    if(ctx == NULL){
        fprintf(stderr, "EVP_CIPHER_new failed : %s\n", ERR_error_string(ERR_get_error(),NULL)); 
        return 2; 
    }
    /* Initialize cypher to aes256gcm which is an auth-encryp mode */ 
    if(1 != EVP_EncryptInit_ex(ctx,params->cipher_type,NULL,NULL,NULL)){
        fprintf(stderr, "EVP_CipherInit_ex failed : %s\n",ERR_error_string(ERR_get_error(),NULL));        
        return 2;
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL); 

    //printf("the out buff after memcpy %s\n", out_buf); 

    /*initializing key and Iv */ 
    //printf("%s , %s \n", params->key, params->iv);
    if(1 != EVP_EncryptInit_ex(ctx,NULL,NULL,params->key,params->iv)){
        fprintf(stderr, "EVP_CipherInit_ex key and iv failed : %s\n",ERR_error_string(ERR_get_error(),NULL));   
        return 2;      
    }

   
    fread(in_buf, sizeof(unsigned char), in_fsize, infile); 
   
    //printf("size of in_buf %d", sizeof(in_buf)); 
    if(1 != EVP_EncryptUpdate(ctx,out_buf, &out_len, in_buf, sizeof(in_buf))){
        fprintf(stderr, "EVP_Encryptupdate failed : %s\n",ERR_error_string(ERR_get_error(),NULL));
        return 2; 
    }

    num_bytes_read = out_len; 
    //printf("numb bytes read %d\n", num_bytes_read); 
 

    if(1 != EVP_EncryptFinal_ex(ctx,out_buf, &out_len)){
        fprintf(stderr, "EVP_Encryptfinal_ex failed : %s\n",ERR_error_string(ERR_get_error(),NULL));        
        return 2;
    }

    num_bytes_read += out_len; 

    if(1 != EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG, 16, tag)){
        fprintf(stderr, "tag getting failed enc");
        return 2; 
    }
    //printf("numb bytes read %d\n", num_bytes_read); 

    /****pub key and sym key encryption ***/ 
    
    char *encrypt = NULL; 
    RSA *rsa_pub, *rsa_pub_read;
    FILE *pubfp = fopen(pemfile, "rb"); 
    rsa_pub = RSA_new(); 
    rsa_pub_read = RSA_new(); 

    rsa_pub_read = PEM_read_RSA_PUBKEY(pubfp, &rsa_pub,0,0);
    fclose(pubfp); 
   
    encrypt= malloc(RSA_size(rsa_pub_read));
    //printf("size of rsa %d\n", sizeof(encrypt));
    int encrypt_len;

    if((encrypt_len = RSA_public_encrypt(AES_256_KEY_SIZE, params->key, (unsigned char*)encrypt, rsa_pub_read, RSA_PKCS1_OAEP_PADDING)) == -1){
        fprintf(stderr, "error encrypting aes key\n"); 
    }
    //printf("size of params key %ld  size of encrypted byte %d \n", sizeof(params->key), encrypt_len); 


    //fwrite(&in_fsize, sizeof(int),1,stdout); 
    //printf("\n\n\n");
    fwrite(encrypt, sizeof(char),encrypt_len,stdout);
    fwrite(params->iv, sizeof(char),AES_BLOCK_SIZE, stdout);
    fwrite(tag,1,16, stdout);  
    fwrite(out_buf,sizeof(char), in_fsize, stdout); 

    /******* end of pub key encryption *****/


    //EVP_PKEY_encrypt(pctx,final_buf, sizeof(final_buf), out_buf, 1);
    //printf("pub encrypted buf %s\n", final_buf); 

    
    fwrite(params->key, sizeof(unsigned char), AES_256_KEY_SIZE, outfile);
    fwrite("\n",sizeof(char), 1, outfile);  
    fwrite(params->iv, sizeof(unsigned char), AES_BLOCK_SIZE, outfile);
    fwrite("\n",sizeof(char), 1, outfile);  
    fwrite(tag,1, 16, outfile); 
    fwrite("\n",sizeof(char), 1, outfile);  
    fwrite(out_buf,sizeof(char), in_fsize, outfile);  
    //printf("final out buff %s\n",out_buf); 

    EVP_CIPHER_CTX_cleanup(ctx);
    RSA_free(rsa_pub); 
    //RSA_free(rsa_pub_read);
    free(encrypt); 



    return 0; 

    //<encrypaes key><encrypted "hello">


}


int decrypt_file(char * priv_pem, char * bin){

    //printf("inside decrypt"); 
    FILE * pem =fopen(priv_pem, "rb");
    FILE *binfile = fopen(bin,"rb");
    if(pem==NULL){
        return 2; 
    }
    if(binfile==NULL){
        return 2; 
    }



    int binsize;
    fseek(binfile, 0, SEEK_END); 
    binsize = ftell(binfile); 
    //printf("%d\n", binsize); 
    rewind(binfile); 

    //printf("binsize %d\n", binsize);
    int textsize = binsize - 256 - AES_BLOCK_SIZE - AES_BLOCK_SIZE; 
    //printf("textsize %d\n", textsize); 
    unsigned char *text = malloc(textsize); 
    if (text == NULL){
        return 2; 
    }
    unsigned char *key[256];
    unsigned char *decryptkey[255];
    unsigned char *iv[AES_BLOCK_SIZE];  
    unsigned char *tag[AES_BLOCK_SIZE];
    unsigned char *keycy[32];



    //fread(key, binsize, 1, binfile); 
    fread(key, 1, 256, binfile);  // read 256 bytes of encry aes key
    fread(iv, 1, 16, binfile); // read iv 
    fread(tag,1,16,binfile);  // read tag 
    fread(text,1,textsize,binfile);  // read text
    
    //printf("iv %s\n", iv);
    //printf("tag %s\n", tag); 
    //memcpy(iv,binf+257, 16); 
    //printf("text %s\n", text);
    //fread(iv,1,AES_BLOCK_SIZE, binfile+256); 

    int rec_text; 
    RSA *rsa_priv, *rsa_priv_read;
    rsa_priv_read= PEM_read_RSAPrivateKey(pem, &rsa_priv, 0,0); 

    rec_text = RSA_private_decrypt(256, (unsigned char*)key,(unsigned char*)decryptkey, rsa_priv_read, RSA_PKCS1_OAEP_PADDING );
    //printf("recovered plain text %d\n", sizeof(iv)); 
    memcpy(keycy,decryptkey,32); 
    //char *num[4]; 
    //fread(num, sizeof(char), 4, binfile);
    //printf("num bytes read from bin file %s\n", &num);
    //printf("decypted key copy %s\n", keycy);

    //printf("decypted key %s\n", decryptkey);


    /********decrypt after priv key decryption *******/
    
    EVP_CIPHER_CTX *ctx;
    int len, plain_text_len; 
    int ret; 
    char * outbuf = malloc(textsize+1); 
    if (outbuf==NULL){
        return 2; 
    }

    if(!(ctx = EVP_CIPHER_CTX_new())){
        fprintf(stderr, "decrypt error init cipher");
        return 2; 
    }

    if(!EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,NULL,NULL)){
        fprintf(stderr, "error init decript op");
        return 2; 
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16,NULL); 

    if(!EVP_DecryptInit_ex(ctx,NULL,NULL,decryptkey,iv)){
        fprintf(stderr, "initialization of key and iv failed in decrypt");
        return 2; 
    }

    if(!EVP_DecryptUpdate(ctx,outbuf, &len,text,textsize)){
        fprintf(stderr, "failed decrypt update");
        return 2; 
    }
    plain_text_len = len ; 
    //printf("plain text len %d\n", plain_text_len);

    if(!EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,16,tag)){
        fprintf(stderr, "tag setting failed in decrypt");
        return 1; 
    }

    ret = EVP_DecryptFinal_ex(ctx,outbuf, &textsize); 

    //printf("ret value %d\n",plain_text_len); 
    EVP_CIPHER_CTX_free(ctx); 
    
    outbuf[plain_text_len]= '\0';
    //printf("out buf %s  out buf last char %c\n", outbuf, outbuf[5]);
    //fwrite(decryptkey,sizeof(char),AES_256_KEY_SIZE,stdout); 
    fwrite(outbuf, sizeof(char), plain_text_len, stdout); 
    fwrite("\n", 1,1, stdout); 

    fclose(pem); 
    fclose(binfile); 
    free(outbuf); 
    free(text); 
    return 0; 

}





int main (int argc, char *argv[]){


    int returnval; 
    if (argc == 4){

        if(strcmp(argv[1],"e")==0){
            unsigned char key[AES_256_KEY_SIZE];
            unsigned char iv[AES_BLOCK_SIZE];
            cipher_params_t *params = (cipher_params_t*)malloc(sizeof(cipher_params_t));

            /*****STRUCT MALLOC CHECK ******/
            if(params == NULL){
                return 1; 
            }
        
            RAND_bytes(iv,sizeof(iv));
            RAND_bytes(key,sizeof(key));
            params->key = key;
            params->iv = iv;
            params->encrypt = 1; 
            params->cipher_type = EVP_aes_256_gcm();

            //printf("About to encrypt\n");
            FILE * f_input, *f_enc;

            int input_fsize = 0; 

            //printf("The key is : %s  and the size is: %d\n", params->key, sizeof(key)); 
            
            f_input = fopen(argv[3], "rb");//text file
            if(f_input == NULL){
                return 1; 
            }
            fseek(f_input,0L, SEEK_END);
            input_fsize = ftell(f_input); 
            fseek(f_input,0L,SEEK_SET); 

            //printf("%d\n", input_fsize);

            f_enc = fopen("contentsfortest.bin","wb");//this is just to "compare" values for decryption file 
            if(f_enc == NULL){
                return 1; 
            }

            returnval = file_encrypt(params, f_input,f_enc,input_fsize, argv[2]);

            fclose(f_input); 
            fclose(f_enc); 
            free(params); 


            return returnval; 
        }


        if(strcmp(argv[1],"d")==0){

            //printf("%s\n",params->key);
            returnval= decrypt_file(argv[2],argv[3]);
            return returnval; 
        }

    }
    if(argc < 4){
        fprintf(stderr, "USAGE:\nif encrypt <programname> <e> <pub pem> <textfile>\nif decrypt <programname> <d> <priv pem> <bin file>\n");
        return 2; 
    }


}