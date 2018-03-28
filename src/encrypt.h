#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include <stdlib.h>

#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
typedef EVP_CIPHER cipher_kt_t;
typedef EVP_CIPHER_CTX cipher_evp_t;
typedef EVP_MD digest_type_t;
#define MAX_KEY_LENGTH EVP_MAX_KEY_LENGTH
#define MAX_IV_LENGTH EVP_MAX_IV_LENGTH
#define MAX_MD_SIZE EVP_MAX_MD_SIZE

#elif defined(USE_CRYPTO_POLARSSL)

#include <polarssl/cipher.h>
#include <polarssl/md.h>
typedef cipher_info_t cipher_kt_t;
typedef cipher_context_t cipher_evp_t;
typedef md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_IV_LENGTH POLARSSL_MAX_IV_LENGTH
#define MAX_MD_SIZE POLARSSL_MD_MAX_SIZE

#elif defined(USE_CRYPTO_MBEDTLS)

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
typedef mbedtls_cipher_info_t cipher_kt_t;
typedef mbedtls_cipher_context_t cipher_evp_t;
typedef mbedtls_md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_IV_LENGTH MBEDTLS_MAX_IV_LENGTH
#define MAX_MD_SIZE MBEDTLS_MD_MAX_SIZE

/* we must have MBEDTLS_CIPHER_MODE_CFB defined */
#if !defined(MBEDTLS_CIPHER_MODE_CFB)
#error Cipher Feedback mode a.k.a CFB not supported by your mbed TLS.
#endif

#endif

#ifdef USE_CRYPTO_APPLECC

#include <CommonCrypto/CommonCrypto.h>

#define kCCAlgorithmInvalid UINT32_MAX
#define kCCContextValid 0
#define kCCContextInvalid -1

typedef struct {
    CCCryptorRef cryptor;
    int valid;
    CCOperation encrypt;
    CCAlgorithm cipher;
    CCMode mode;
    CCPadding padding;
    uint8_t iv[MAX_IV_LENGTH];
    uint8_t key[MAX_KEY_LENGTH];
    size_t iv_len;
    size_t key_len;
} cipher_cc_t;

#endif

//jst add
#define SODIUM_BLOCK_SIZE   64

enum crpher_index {
    NONE,
    TABLE,
    RC4,
    RC4_MD5_6,
    RC4_MD5,
    AES_128_CFB,
    AES_192_CFB,
    AES_256_CFB,
    AES_128_CTR,
    AES_192_CTR,
    AES_256_CTR,
    BF_CFB,
    CAMELLIA_128_CFB,
    CAMELLIA_192_CFB,
    CAMELLIA_256_CFB,
    CAST5_CFB,
    DES_CFB,
    IDEA_CFB,
    RC2_CFB,
    SEED_CFB,
    SALSA20,
    CHACHA20,
    CHACHA20IETF,
    CHACHA20POLY1305IETF,
    CIPHER_NUM
};


typedef struct buffer {
    size_t idx;
    size_t len;
    size_t capacity;
    char   *array;
} buffer_t;


typedef struct {
    uint8_t *enc_table;
    uint8_t *dec_table;
    uint8_t enc_key[MAX_KEY_LENGTH];
    int enc_key_len;
    int enc_iv_len;
    int enc_method;
    
    struct cache *iv_cache;
} cipher_env_t;


typedef struct {
    cipher_evp_t *evp;
#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t cc;
#endif
    uint8_t iv[MAX_IV_LENGTH];
} cipher_ctx_t;

typedef struct {
    cipher_kt_t *info;
    size_t iv_len;
    size_t key_len;
} cipher_t;


typedef struct enc_ctx {
    uint8_t init;
    uint64_t counter;
    cipher_ctx_t evp;
} enc_ctx_t;
#define ADDRTYPE_MASK 0xEF
#define ONETIMEAUTH_FLAG 0x10

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))
//end

#define MD5_BYTES 16U
#define SHA1_BYTES 20U

int ss_md5_hmac(char *auth, char *msg, int msg_len, uint8_t *iv, int enc_iv_len, uint8_t *enc_key, int enc_key_len);
int ss_md5_hmac_with_key(char *auth, char *msg, int msg_len, uint8_t *auth_key, int key_len);
int ss_md5_hash_func(char *auth, char *msg, int msg_len);
int ss_sha1_hmac(char *auth, char *msg, int msg_len, uint8_t *iv, int enc_iv_len, uint8_t *enc_key, int enc_key_len);
int ss_sha1_hmac_with_key(char *auth, char *msg, int msg_len, uint8_t *auth_key, int key_len);
int ss_sha1_hash_func(char *auth, char *msg, int msg_len);
int ss_aes_128_cbc(char *encrypt, char *out_data, char *key);

void bytes_to_key_with_size(const char *pass, size_t len, uint8_t *md, size_t md_size);
//jst add
int balloc(buffer_t *ptr, size_t capacity);
int brealloc(buffer_t *ptr, size_t len, size_t capacity);
void bfree(buffer_t *ptr);

int ss_encrypt_all(cipher_env_t* env, buffer_t *plaintext, size_t capacity);
int ss_decrypt_all(cipher_env_t* env, buffer_t *ciphertext, size_t capacity);
int ss_encrypt(cipher_env_t* env, buffer_t *plaintext, enc_ctx_t *ctx, size_t capacity);
int ss_decrypt(cipher_env_t* env, buffer_t *ciphertext, enc_ctx_t *ctx, size_t capacity);

void enc_ctx_init(cipher_env_t *env, enc_ctx_t *ctx, int enc);
void enc_ctx_release(cipher_env_t* env, enc_ctx_t *ctx);

int enc_get_iv_len(cipher_env_t* env);
uint8_t* enc_get_key(cipher_env_t* env);
int enc_get_key_len(cipher_env_t *env);
void enc_release(cipher_env_t *env);
int enc_init(cipher_env_t *env, const char *pass, const char *method);

int ss_encrypt_buffer(cipher_env_t *env, enc_ctx_t *ctx, char *in, size_t in_size, char *out, size_t *out_size);
int ss_decrypt_buffer(cipher_env_t *env, enc_ctx_t *ctx, char *in, size_t in_size, char *out, size_t *out_size);
#endif // _AUTH_H
