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

#define FILELEN 2592
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

int ascii_to_hex(char c)
{
        int num = (int) c;
        if(num < 58 && num > 47)
        {
                return num - 48; 
        }
        if(num < 103 && num > 96)
        {
                return num - 87;
        }
        return num;
}

// uint8_t getmostfrequent(uint8_t arra[81][16]){
//     int i=0,j=0,count=0;
//     for(i=0;i<16;i++){
//         for(j=0;j<81;j++){
//             if(arra[j][i]!=0){
//                 arra[j][i]
//             }
        
//         }
//     }
// }

static void test_encrypt_ecb_verbose(void)
{
FILE *fp = fopen("fault_attack_without_nl.txt","r");
unsigned char c1,c2;
int i=0,j=0,n=0,m=0,k=0,p=0,r=0,q=0;
uint8_t l=0x00;
uint8_t e[8]={0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
uint8_t correct_key[32], xor[81][16], fault_key[32], pred[2040],possible[81][16][14]={0}, a[16], mid[4][4], shift_key[16], temp[14],temp1[14],temp2[14],key[16],mat[4][4];
uint8_t a2[16],a3[4][4], a4[16];
unsigned char sum,final_hex[FILELEN/2];
for(i=0;i<FILELEN/2;i++)
{
    c1 = ascii_to_hex(fgetc(fp));
    c2 = ascii_to_hex(fgetc(fp));
    sum = c1<<4 | c2;
    final_hex[i] = sum;
}
for(j=0;j<16;j++){
    correct_key[j]=final_hex[j];
}
printf("The correct Cipher text is \n");
phex(correct_key);

for(i=0;i<FILELEN/2; i+=16){
    n=0;
    for(j=i;j<i+16;j++){
        fault_key[n] = final_hex[j];
        n++; 
    }
    for(j=0;j<16;j++){
        xor[m][j] = correct_key[j]^fault_key[j];
    }
                
    // printf("\nAfter XOR: ");                               Uncomment to print all XOR values
    // for(k=0;k<16;k++){
    //     printf("%2x",xor[m][k]);
    // }
    m++;
}
for(l=0x0;l<0xff;l+=0x01){
    for(j=0;j<8;j++){
        pred[p] = getSBoxValue(l)^getSBoxValue((l^e[j])); 
        m=0; 
        int q=0;
        while(m<81){
            for(n=0;n<16;n++){
                if(xor[m][n]==pred[p]){
                    while(possible[m][n][q]!=0){
                        q++;
                    }
                    possible[m][n][q]=l;
                }
            }
            m++;
        }
        p++;
    }
}
                

                //printf("\n\npossible matrix\n");
for(k=0;k<16;k++){
    int v=0;
    for(i=0;i<81;i++){
        if(possible[i][k][0]!=0){
            for(j=0;j<14;j++){   
                for(r=0;r<14;r++){
                    if((possible[i][k][j]!=0) && (possible[i][k][j]==possible[i+1][k][r])){
                        temp[v]=possible[i][k][j];
                        v++;
                    }
                }
                v=0;
                for(r=0;r<14;r++){
                    if(temp[v]==possible[i+2][k][r]){
                        temp1[v]= temp[v];
                        v++;
                    }
                }
                v=0;
                for(r=0;r<14;r++){
                    if(temp1[v]==possible[i+3][k][r]){
                        temp2[v]= temp1[v];
                        v++;
                    }
                }
                v=0;
                for(r=0;r<14;r++){
                    if(temp2[v]==possible[i+4][k][r]){
                        a[k]= temp2[v];
                    }
                }
            }
        }
    }             
}       

printf("\n9th Round Output is: ");
for(i=0;i<16;i++){
    printf("%2x", a[i]);
}
for(i=0;i<16;i++){
    a2[i]=getSBoxValue(a[i]); // output of s box
}
int c=0;
for(i=0;i<4;i++){
    for(j=0;j<4;j++){
        a3[j][i]=a2[c]; // make a matrix to input to shift row.
        c++;
    }
}
ShiftRows(a3);
int d=0;
for(i=0;i<4;i++){
    for(j=0;j<4;j++){
        a4[d]=a3[j][i]; // convert the matrix to strinf to XOR with the cipher text
        d++;
    }
}

printf("\n");
for(i=0;i<16;i++){
    key[i]=a4[i]^correct_key[i]; // XOR with cipher text to get correct round key(correct key -- is correct cipher text)
}
printf("\nThe retrieved round key is: ");
for(i=0;i<16;i++){
    printf("%.2x", key[i]);
}
printf("\n");
int b=0;
for(i=0;i<4;i++){
    for(j=0;j<4;j++){
        mat[j][i]=key[b];
        b++;
    }
}
InvShiftRows2(mat);
b=0;
for ( i = 0; i <4; i++)
{
    for(j=0;j<4;j++){
        shift_key[b]=mat[j][i];
        b++;
    }
}
printf("\n(Round key) shift_Key is: ");
for(i=0;i<16;i++){
    printf("%.2x", shift_key[i]);
}

Printf("\n Inverse key scheduling part commented in aes.c file -- some problem in logic.");

}
