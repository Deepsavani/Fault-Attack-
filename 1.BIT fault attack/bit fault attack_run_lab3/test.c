#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"
#include "aes.c"

typedef uint8_t state_t[4][4];

static void phex(uint8_t* str);
static void test_encrypt_ecb_verbose(void);
char* itoa(int value, char* result, int base) ;
int main(void)
{
    int exit;

#if defined(AES256)
    printf("\nTesting AES256\n\n");
#elif defined(AES192)
    printf("\nTesting AES192\n\n");
#elif defined(AES128)
    printf("\nTesting AES128\n\n");
#else
    printf("You need to specify a symbol between AES128, AES192 or AES256. Exiting");
    return 0;
#endif

    test_encrypt_ecb_verbose();

    return 0;
}


// prints string as hex
static void phex(uint8_t* str)
{

#if defined(AES256)
    uint8_t len = 32;
#elif defined(AES192)
    uint8_t len = 24;
#elif defined(AES128)
    uint8_t len = 16;
#endif

    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

static void test_encrypt_ecb_verbose(void)
{
    // Example of more verbose verification

    uint8_t i,j,wrap_b[16][2], b[2];
    
    
    // 128bit key
    uint8_t key[16] = { (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00 };
    // 512bit text
    struct AES_ctx ctx;
        AES_init_ctx(&ctx, key);

    // uint8_t temp[32] = {        (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
    //                             (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
    //                             (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
    //                             (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00};

    

uint8_t a,x,y,m, plain_text[32],rk0[32];
uint8_t encrypt_new[32],encrypt_previous[32],xor[32];
for(x=(uint8_t)0; x<(uint8_t)16; x++){ 
    uint8_t temp[32] = {        (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
                                (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
                                (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00,
                                (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00, (uint8_t) 0x00};
                                
    memcpy(plain_text, temp, 16);
    for(y=(uint8_t)0; y<=(uint8_t)254; y++){
        AES_init_ctx(&ctx, key);
        a=0; 
        printf("OLD Input text : \n ");
        phex(plain_text);
        AES_ECB_encrypt_scan(&ctx, plain_text);
        memcpy(encrypt_previous, plain_text, 16);
        temp[x]=temp[x]+(0x01);
        //abc[x] = temp[x]+(0x02);
        memcpy(plain_text, temp, 16);
        printf(" NEW Input text : \n ");
        phex(plain_text);
        AES_ECB_encrypt_scan(&ctx, plain_text);
        memcpy(encrypt_new, plain_text, 16);
        temp[x]=temp[x]+(0x01);
        memcpy(plain_text, temp, 16);
        printf("encrypt new=\n");
        phex(encrypt_new);
        printf("encrypt previous=\n");
        phex(encrypt_previous);
        for(i=0;i<16;i++)
        {
            xor[i]=encrypt_new[i]^encrypt_previous[i];
        }
        printf("Ye XOR hai\n");
        phex(xor);

        for(i=0; i<16; i++){
            for(j=0;j<8;j++){
            if(xor[i]&1){
                a++;
            }
            xor[i]>>=1;
            
        }
        }
        printf("\nNumber of ones = ");
        printf("%d\n",a);
        if(a==9){
            wrap_b[x][0] = 226;
            wrap_b[x][1] = 227;
            printf("\n a value = %.2x\n",encrypt_new[x]);
            rk0[x]=(encrypt_new[x])^(0xE3);
            //printf("%s", *wrap_b);
            printf("\n------------------------break -----------------------\n");
            break;
        }
        else if(a==12){
            wrap_b[x][0] = 242;
            wrap_b[x][1] = 243;
            printf("\n a value = %.2x\n",encrypt_new[x]);
            rk0[x]=(encrypt_new[x])^(0xF3);
            //printf("%s", *wrap_b);
            printf("\n------------------------break -----------------------\n");
            break;
        }
        else if(a==23){
            wrap_b[x][0] = 122;
            wrap_b[x][1] = 123;
            printf("\n a value = %.2x\n",encrypt_new[x]);
            rk0[x]=(encrypt_new[x])^(0x7B);
            //printf("%s", *wrap_b);
            printf("\n------------------------break -----------------------\n");
            break;
        }
        else if(a==24){
            wrap_b[x][0] = 130;
            wrap_b[x][1] = 131;
            printf("\n a value = %.2x\n",encrypt_new[x]);
            rk0[x]=(encrypt_new[x])^(0x83);
            printf("%s", *wrap_b);
            printf("\n------------------------break -----------------------\n");
            break;
            }
        else{
            // temp[x]=temp[x]+(0x01);
            // memcpy(plain_text, temp, 16);
            continue;
        }
    }

    continue;
}

printf("rk0 ------\n");
phex(rk0);

//  for(i=0;i<16;i++){
//      for(j=0;j<2;j++){
//      printf("%d ", wrap_b[i][j]);
//      if(j==1){
//          printf("\n");
//      }
//     }
//  }

//  for(i=0;i<16;i++){
//      uint8_t temp[32] = {       (uint8_t) 0x0d, (uint8_t) 0x09, (uint8_t) 0x77, (uint8_t) 0x14,
//                                 (uint8_t) 0x03, (uint8_t) 0xc0, (uint8_t) 0xae, (uint8_t) 0x00,
//                                 (uint8_t) 0x98, (uint8_t) 0x1f, (uint8_t) 0x97, (uint8_t) 0x00,
//                                 (uint8_t) 0x29, (uint8_t) 0x16, (uint8_t) 0x00, (uint8_t) 0xd0}; 
//      temp[x]=temp[x]+0x05;
//      AES_ECB_encrypt(&ctx, temp);
//      encrypt_round1[x] = (*temp)[x];
//  }
//  printf("\nValue here is this: ");
//  phex(encrypt_round1);
 

    // for(i=0; i<len(plain_text); i+=1){
    //     uint8_t new_text[64] = plain_text + 1;                         
    // print text to encrypt, key and IV
    // printf("ECB encrypt verbose:\n\n");
    // printf("plain text:\n");
 
    //     phex(plain_text + i * (uint8_t) 16);
    
    // printf("\n");

    // printf("key:\n");
    // phex(key);
    // printf("\n");

    // print the resulting cipher as 4 x 16 byte strings
    
  
    
    //uint8_t k,l;
    //c = AES_ECB_encrypt(&ctx, plain_text + (i * 16));
    //d = AES_ECB_encrypt(&ctx, plain_text_two + (i * 16));

  
    // printf("\nAfter XOR: ");

    //  for(k=0; k<4; ++k){
    //   for(l=0;l<4;++l){
    //     e.arr[k][l]=(c.arr[k][l])^(d.arr[k][l]);
    //   }
    // }

    // printf("\n");
    // for(k=0; k<4; ++k){
    //   for(l=0;l<4;++l){
    //     printf("%.2x", e.arr[k][l]);
    //   }
    // }
}