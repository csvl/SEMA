#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <sys/stat.h>   // stat

#define password "SwagPassword"
#define theFakeFlag "Swag{this_is_not_the_flag}"
#define ImNice "-------------- RC4 ---------------"


static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

#define KEYSIZE 32
#define PATH_MAX 4096

char PASS[] =  {0x13, 0xec, 0x4d, 0x7a, 0x4a, 0x78, 0x4f, 0xd0, 0xe8, 0xa8, 0xf1, 0x90, 0x0a, 0x24, 0xdb, 0xc0, 0x00};  //"RR4luwNxJguISgrQ" //"Password1234"

unsigned char key[KEYSIZE];


int alt_f4(char *filename) {
  struct stat   buffer;  
  //printf("%i\n",stat (filename, &buffer));
  if(stat (filename, &buffer) == 0) return 1; 
  return 0;
}

int hv_bit(){
    int cpu_feats=0;
    __asm__ volatile (" cpuid "
            : "=c" ( cpu_feats ) // output : ecx or rcx -> cpu_feat
            : "a" (1));          // input : 1 -> eax or rax
    return (cpu_feats >> 31) & 1;
}


void keygen(char *name) {
	int i=0;
	unsigned char *h = SHA256(name, strlen(name), 0);
	memcpy(key, h, strlen(h));
	while (i < KEYSIZE) {
		//printf("DEBUG: key[%i]=%u\n",i,key[i]);
		i++;
	}
}

void build_table() {
    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void cleanup() {
    free(decoding_table);
}

char *encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

char swagVal[] = "FLOG{AntiFLAG}";

unsigned char *decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_table();

    //printf("DEBUG: input_length=%i\n",input_length);

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;
    //printf("DEBUG: output_length=%i\n",*output_length);
    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
        // if (j < *output_length) printf(decoded_data[j-1]);
        printf("a");
    }
    printf("DEBUG: output_length=%i\n",*output_length);
    printf(decoded_data);
    printf("\n");
    return decoded_data;
}

// apt-get install libssl-dev:i386
// gcc -m32 -o advanced_challenge advanced_challenge.c -O0 -lssl -lcrypto -static

/* swagish_transformers() -- Encrypt data using RC4 encryption algorithm.
 *
 * Args:
 *     data - Data to encrypt
 *     size - Length of data
 *     key  - Passphrase to encrypt data with.
 *
 * Returns:
 *     0 if successful.
 *     1 if unsuccessful.
 */
int swagish_transformers(unsigned char *data, size_t size, const unsigned char *key) {
  int           i;
  int           rc4i;
  int           rc4j;
  unsigned char rc4s[256];
  unsigned int  tmp;

  if (strlen((char *)key) > sizeof(rc4s)) {
    fprintf(stderr, "Key must be under %ld bytes\n", sizeof(rc4s));
    return 1;
  }

  /* Key-scheduling algorithm */
  for (i = 0; i < sizeof(rc4s); i++)
    rc4s[i] = i;

  for (rc4i = 0, rc4j = 0; rc4i < sizeof(rc4s); rc4i++) {
    rc4j = (rc4j + rc4s[rc4i] + key[rc4i % strlen((char *)key)]) % sizeof(rc4s);

    /* swap s[i] and s[j] */
    tmp = rc4s[rc4j];
    rc4s[rc4j] = rc4s[rc4i];
    rc4s[rc4i] = tmp;
  }

  /* encrypt data */
  for (rc4i = 0, rc4j = 0, i = 0; i < size; i++) {
    rc4i = (rc4i + 1) % sizeof(rc4s);
    rc4j = (rc4j + rc4s[rc4i]) % sizeof(rc4s);

    /* swap s[i] and s[j] */
    tmp = rc4s[rc4j];
    rc4s[rc4j] = rc4s[rc4i];
    rc4s[rc4i] = tmp;

    tmp = rc4s[(rc4s[rc4i] + rc4s[rc4j]) % sizeof(rc4s)];
    data[i] ^= tmp;
  }

  return 0;
}


int check_debugger() {
    if (ptrace(PTRACE_TRACEME, 0) < 0) {
        return 1;
    }
    return 0;
}

void anti_debug() {
    if (check_debugger()) {
        printf("Sorry, this program cannot be run under a debugger.\n");
        exit(1);
    }
}

/*
./advanced_challenge
Enter the password to reveal the flag: ImAmADebuuggerrrrMan
Congratulations! The flag is FLAG{_}
*/
int main(int argc, char **argv) {
    if (argc > 2) return -1;
    int timeout = 0;
    if (argc == 2) 
        timeout = atoi(argv[1]);

    anti_debug();

    //deadcode
    char key1[6] = {97, 32, 99, 100, 101, 102};
    char key2[6] = {102, 101, 100, 99, 98, 97};
    char key3[6] = {120, 121, 122, 97, 98, 99};
    char key4[6] = {99, 98, 97, 122, 42, 120};
    char key5[6] = {49, 50, 51, 52, 53, 54};
    char key6[6] = {54, 53, 52, 51, 50, 49};
    char flag_encrypted[14] = {62, 32, 35, 34, 34, 52, 42, 50, 54, 32, 55, 33, 32, 60};
    char *flag = malloc(14);
    for (int i = 0; i < 14; i++) {
        if (i < 2) {
            flag[i] = flag_encrypted[i] ^ key1[i];
        } else if (i < 4) {
            flag[i] = flag_encrypted[i] ^ key2[i];
        } else if (i < 6) {
            flag[i] = flag_encrypted[i] ^ key3[i];
        } else if (i < 8) {
            flag[i] = flag_encrypted[i] ^ key4[i];
        } else if (i < 10) {
            flag[i] = flag_encrypted[i] ^ key5[i];
        } else if (i < 12) {
            flag[i] = flag_encrypted[i] ^ key6[i];
        } else {
            flag[i] = flag_encrypted[i];
        }
    }

    int dead_code_1 = 1;
    int dead_code_2 = 2;
    int dead_code_3 = 3;
    int dead_code_4 = 4;
    int dead_code_5 = 5;
    int dead_code_6 = 6;
    int dead_code_7 = 7;
    int dead_code_8 = 8;
    int dead_code_9 = 9;
    int dead_code_10 = 10;
    int dead_code_11 = 11;
    size_t* output_length;
    char *decoded_b64;
    int success;
    

    if(dead_code_1 == 1) {
        if(dead_code_2 == 2) {
            if(dead_code_3 == 3) {
                if(dead_code_4 == 4) {
                    if(dead_code_5 == 5) {
                        if(dead_code_6 == 6) {
                            if(dead_code_7 == 7) {
                                if(dead_code_8 == 8) {
                                    if(dead_code_9 == 9) {
                                        if(dead_code_10 == 10) {
                                            if(dead_code_11 == 11) {
                                                char input[25];
                                                printf("Enter the password to reveal the flag: ");
                                                fgets(input, 25, stdin);
                                                input[strcspn(input, "\n")] = 0;
                                                printf("Waiting for something to happen... :O\n");
                                                sleep(timeout);
                                                output_length = malloc(sizeof(size_t));
                                                decoded_b64   = encode(input, strnlen(input,25), output_length); // base64: UGFzc3dvcmQxMjM0
                                                success       = swagish_transformers(decoded_b64, strnlen(decoded_b64,50), "passphrase"); //rc4 decryption with "passphrase"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    
    printf("Waiting for something to happen... :O\n");
    printf("Waiting for your like on our github repository: SEMA-Toolchain & QUIC-FormalVerification ...\n");
    sleep(timeout); // time to take the dump TODO add paramter for timeout

    if (strncmp(decoded_b64, PASS,25) == 0) {

        // check if files is present in current folder
        char cwd_file[PATH_MAX];
        if (getcwd(cwd_file, sizeof(cwd_file)) != NULL) {
            printf("Current working dir: %s\n", cwd_file);
            char path[1024] ;   // or some other number
            strcpy(path,cwd_file);
            // then separator
            strcat(path, "/") ; // or "\\" in Windows
            strcat(path, "iLoveLINGI2144.required");
            //printf("Current working dir: %s\n", path);
            int is_pres = alt_f4(path);
            printf("Doing tons of calculations\n");
            sleep(timeout);
            if(is_pres == 0) {
                printf("Sorry, you miss something... :(\n");
                exit(1);
            }
            FILE *fil = fopen(path, "r");
            if (!fil) {
                exit(EXIT_FAILURE); 
            };
            char*linbuf = NULL; 
            size_t siz = 0;
            ssize_t linlen = 0;
            int count = 0;
            while ((linlen=getline(&linbuf, &siz, fil))>0) {
                // linbuf contains the current line
                // linlen is the length of the current line
                //printf("%s\n", linbuf);
                int is_cmp = strcmp(linbuf, "I will take a cyber security master thesis\n");
                if(is_cmp == 0) count = count + 1;
            };
            fclose(fil);
            free(linbuf), 
            linbuf=NULL;
            linlen = 0, 
            siz = 0;

            if(count != 42) {
                //printf("%d\n", count);
                printf("Sorry, you miss something... :( :( :(\n");
                exit(1);
            } 

            keygen(decoded_b64); //TODO add argv[0] ?
            char buf [] = {0x7c ,0xd9 ,0xa2 ,0x3b ,0xe8 ,0x4d ,0x81 ,0x49 ,0x7d ,0xca ,0x3d ,0x8a ,0x2f ,0xa6 ,0x9b ,0x9b ,0x52 ,0x96
                          ,0xb3 ,0x26 ,0x82 ,0x33 ,0xc2 ,0x9c ,0xc4 ,0x68 ,0x75 ,0x62 ,0x2e ,0x63 ,0x6f ,0x6d ,0x5f ,0xb5 ,0xa3 ,0x24 
                          ,0xdf ,0x8e ,0x80 ,0x13 ,0xae ,0xb8 ,0x1d ,0x59 ,0x22 ,0xcc ,0xa2 ,0x99 ,0x4b ,0x87 ,0xac ,0x42 ,0xb8 ,0x76 
                          ,0xc4 ,0x99 ,0xb9 ,0x63 ,0x61 ,0x74 ,0x69 ,0x6f ,0x6e, 0x00}; 
            //"Liker le git: https://github.com/ElNiak/QUIC-FormalVerification";
            int j = 0;
            while (j < strlen(buf)){
                int jj = 0;
                while (jj < KEYSIZE) {
                    buf[j] = buf[j] + key[jj]; //addition/substraction method to encode/decode
                    j++;
                    jj++;
                }
            }
            printf("Congratulations! The flag is FLAG{%s}\n", buf);
        }
    } else {
        printf("Incorrect password. Exiting...\n");
    }
    free(flag);
    return 0;
}
