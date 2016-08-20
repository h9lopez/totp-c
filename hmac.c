#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "hmac.h"
#define HMAC_BLOCKSIZE 64 // bytes
#define SHA1_DIGESTSIZE 20


void printHex(unsigned char *str, size_t len)
{
    for (int i = 0; i < len; i++)
    {
        fprintf(stderr, "%02x", *(str+i));
    }
}

void xormem(unsigned char *m1, unsigned char *m2, size_t len)
{

    for (int i = 0; i < len; i++)
    {
        m1[i] = m1[i] ^ m2[i];
    }
}

unsigned char *hmac_sha1(unsigned char *key, size_t keylen,
                         unsigned char *msg, size_t msglen)
{

    unsigned char *new_key = NULL;
    unsigned char *o_keypad = NULL;
    unsigned char *i_keypad = NULL;

    fprintf(stderr, "Key to be used: ");
    printHex(key, keylen);
    fprintf(stderr, "\n");

    if (keylen > HMAC_BLOCKSIZE) {
        fprintf(stderr, "Key too big, hashing\n");
        new_key = (unsigned char *)malloc( sizeof(unsigned char) * (SHA1_DIGESTSIZE) );
        memset(new_key, 0x0, sizeof(unsigned char) * (SHA1_DIGESTSIZE));
        SHA1(key, keylen, new_key);
        key = new_key;
        keylen = SHA1_DIGESTSIZE;
        fprintf(stderr, "New key: " );
        printHex(key, keylen);
        fprintf(stderr, ", new keylen: %d\n", keylen);
        fprintf(stderr, "\n");
    }

    if (keylen < HMAC_BLOCKSIZE) {
        fprintf(stderr, "Key too small, padding...\n");
        new_key = (unsigned char *)malloc( sizeof(unsigned char) * (HMAC_BLOCKSIZE) );
        memset(new_key, 0x0, sizeof(unsigned char) * (HMAC_BLOCKSIZE));
        memcpy(new_key, key, keylen);
        key = new_key;
        keylen = HMAC_BLOCKSIZE;
        fprintf(stderr, "New key: ");
        printHex(key, keylen);
        fprintf(stderr, ", new keylen: %d\n", keylen);
        fprintf(stderr, "\n");
    }

    // TODO: Error checks
    o_keypad = (unsigned char *)malloc( sizeof(unsigned char)*HMAC_BLOCKSIZE );
    i_keypad = (unsigned char *)malloc( sizeof(unsigned char)*HMAC_BLOCKSIZE );

    memset(o_keypad, 0x5c, HMAC_BLOCKSIZE);
    memset(i_keypad, 0x36, HMAC_BLOCKSIZE);

    fprintf(stderr, "o_keypad before: ");
    printHex(o_keypad, HMAC_BLOCKSIZE);
    fprintf(stderr, "\ni_keypad before: ");
    printHex(i_keypad, HMAC_BLOCKSIZE);
    fprintf(stderr, "\n");

    xormem(o_keypad, key, HMAC_BLOCKSIZE);
    xormem(i_keypad, key, HMAC_BLOCKSIZE);

    unsigned char *inner_message = NULL;
    unsigned char *inner_message_digest = NULL;
    unsigned char *outer_message = NULL;
    unsigned char *outer_message_digest = NULL;

    // Concat i_keypad + message
    inner_message = (unsigned char *)malloc( (sizeof(unsigned char)*HMAC_BLOCKSIZE) +
                        ( sizeof(unsigned char)*msglen ) );
    memcpy(inner_message, i_keypad, HMAC_BLOCKSIZE);
    memcpy(inner_message+HMAC_BLOCKSIZE, msg, msglen);
    fprintf(stderr, "Inner message is: ");
    printHex(inner_message, HMAC_BLOCKSIZE + msglen);
    fprintf(stderr, "\n");

    inner_message_digest = (unsigned char *)malloc( sizeof(unsigned char)*SHA1_DIGESTSIZE );
    SHA1(inner_message, HMAC_BLOCKSIZE+msglen, inner_message_digest);
    fprintf(stderr, "Inner message digest is: ");
    printHex(inner_message_digest, SHA1_DIGESTSIZE);
    fprintf(stderr, "\n");

    outer_message = (unsigned char *)malloc( (sizeof(unsigned char)*HMAC_BLOCKSIZE) +
                                ( sizeof(unsigned char)*SHA1_DIGESTSIZE ));
    memcpy(outer_message, o_keypad, HMAC_BLOCKSIZE);
    memcpy(outer_message+HMAC_BLOCKSIZE, inner_message_digest, SHA1_DIGESTSIZE);
    fprintf(stderr, "Outer message is: ");
    printHex(outer_message, HMAC_BLOCKSIZE + SHA1_DIGESTSIZE);
    fprintf(stderr, "\n");

    outer_message_digest = (unsigned char *)malloc(sizeof(unsigned char)*SHA1_DIGESTSIZE);
    SHA1(outer_message, HMAC_BLOCKSIZE+SHA1_DIGESTSIZE, outer_message_digest);
    fprintf(stderr, "Outer message digest: ");
    printHex(outer_message_digest, SHA1_DIGESTSIZE);
    fprintf(stderr, "\n");

    free(outer_message);
    free(inner_message_digest);
    free(inner_message);
    free(o_keypad);
    free(i_keypad);
    return outer_message_digest;
}


int main(void)
{

	struct test_case *test = NULL;
    unsigned char *digest = NULL;
	for (int i = 0; i < SHA1_TEST_VECTORS_NUM; i++)
	{
        printf("---------------------new test-------------------\n");
		test = &sha1_test_vectors[i];
		digest = hmac_sha1(test->key, test->keylen,
					test->data, test->datalen);

        if (strncmp(digest, test->expected, test->expectedlen) == 0) {
            printf("\t[OK] Digests match\n\n");
        } else {
            printf("\t[ERR] Digests do not match!\n");
            printf("\t\tOurs: ");
            printHex(digest, SHA1_DIGESTSIZE);
            printf("\n\t\tTheirs: ");
            printHex(test->expected, test->expectedlen);
            printf("\n");
            exit(0);
        }

	}

    printf("[ALL OK] All tests passed!\n");
    return 0;
}
